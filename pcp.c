/* 
 * TODO:
 *  - make an ssh connection that O_TRUNCs the file, then continue with the rest of the threads
 *  - configurable location of remote pcp binary
 *  - more gracefully handle not being in known_hosts
 */

#include <libssh/libssh.h> 
#include <libssh/callbacks.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>

#define DEFAULT_NUMBER_OF_THREADS 4
#define MAX_THREADS 255
#define MIN_THREADED_COPY_SIZE 1024 // must be greater than MAX_THREADS
#define BLOCK_SIZE 1048576
#define REMOTE_COMMAND_TO_EXECUTE "~/source/pcp/pcp"

struct {
    ssh_session ssh_opts;
    int server_mode;
    int threads;
    char *input_filename;
    char *output_filename;
    char *hostname;
    off_t file_offset;
    size_t file_size;
} config;

struct instruction {
    ssh_session session;
    int fd;
    off_t offset;
    size_t size;
};

int load_config(int argc, char *argv[]) {
    char c;

    config.ssh_opts = ssh_new();
    if (argc > 1 && strcmp(argv[1], "-$")) {
        ssh_options_getopt(config.ssh_opts, &argc, argv);
    }

    config.threads = DEFAULT_NUMBER_OF_THREADS;

    while ((c = getopt(argc, argv, "$t:")) != -1) {
        switch (c) {
            case '$':
                config.server_mode = 1;
                break;

            case 't':
                config.threads = atoi(optarg);
                if (config.threads < 1 || config.threads > MAX_THREADS) {
                    fprintf(stderr, "threads must be between 1 and %d\n", MAX_THREADS);
                    return -1;
                }
                break;
        }
    }

    if (config.server_mode) {
        if (optind != argc - 3) {
            fprintf(stderr, "expected three arguments: local filename, offset and length\n");
            return -1;
        }
        config.input_filename = argv[optind];
        config.file_offset = atol(argv[optind + 1]);
        config.file_size = atol(argv[optind + 2]);
    }
    else {
        if (optind != argc - 2) {
            fprintf(stderr, "expected two arguments, local filename and ssh host\n");
            return -1;
        }
        config.input_filename = argv[optind];

        char *dest = argv[optind + 1];
        char *colon = strchr(dest, ':');
        if (colon == NULL) {
            fprintf(stderr, "destination must be in the form host:[filename]\n");
            return -1;
        }
        *colon = 0;
        config.hostname = dest;
        colon++;
        if (*colon) {
            config.output_filename = colon;
        }
        else {
            char *filename_only = strrchr(config.input_filename, '/');
            config.output_filename = filename_only ? filename_only + 1 : config.input_filename;
        }

        ssh_options_set(config.ssh_opts, SSH_OPTIONS_HOST, config.hostname);
    }

    printf("server_mode=%d, threads=%d, filename=%s\n", config.server_mode, config.threads, config.input_filename);

    return 0;
}

int connect_to_host(struct instruction *instruction) {
    if (ssh_connect(instruction->session) != SSH_OK) {
        fprintf(stderr, "Error connecting: %s\n", ssh_get_error(instruction->session));
        return -1;
    }
    return 0;
}

ssh_channel set_up_ssh_channel(struct instruction *instruction) {
    if (ssh_is_server_known(instruction->session) != SSH_SERVER_KNOWN_OK) {
        fprintf(stderr, "Unknown server.  Add it to your known_hosts before using pcp.\n");
        return NULL;
    }

    if (ssh_userauth_autopubkey(instruction->session, NULL) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "You must have a key loaded in the ssh agent before connecting to this server.\n");
        return NULL;
    }

    ssh_channel channel = ssh_channel_new(instruction->session);
    if (channel == NULL) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(instruction->session));
        return NULL;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(instruction->session));
        ssh_channel_free(channel);
        return NULL;
    }

    return channel;
}

int transfer_data(struct instruction *instruction, ssh_channel channel) {
    size_t command_length = strlen(config.output_filename);

    if (command_length > 65535) {
        fprintf(stderr, "unreasonably long output filename, aborting");
        abort();
    }

    command_length += strlen(REMOTE_COMMAND_TO_EXECUTE) + 256;

    char *command = (char *)malloc(command_length);
    if (command == NULL) abort();

    int n = snprintf(command, command_length, "%s -$ %s %lld %ld", REMOTE_COMMAND_TO_EXECUTE, config.output_filename, instruction->offset, instruction->size);
    if (n >= command_length) abort();

    fprintf(stderr, "running %s\n", command);

    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        fprintf(stderr, "Error running command on SSH channel: %s\n", ssh_get_error(instruction->session));
        free(command);
        return -1;
    }

    free(command);

    if (lseek(instruction->fd, instruction->offset, SEEK_SET) == -1) {
        perror("lseek");
        return -1;
    }

    char *buffer = (char *)malloc(BLOCK_SIZE);
    if (buffer == NULL) abort();

    size_t size = instruction->size;
    while (size > 0) {
        ssize_t n = read(instruction->fd, buffer, size < BLOCK_SIZE ? size : BLOCK_SIZE);
        if (n <= 0) {
            perror("read");
            free(buffer);
            return -1;
        }
        ssize_t written = ssh_channel_write(channel, buffer, n);
        if (written != n) {
            fprintf(stderr, "ssh channel didn't accept all bytes, %ld left to go\n", size - written);
            free(buffer);
            return -1;
        }
        size -= n;
    }

    free(buffer);
    ssh_channel_send_eof(channel);

    return 0;
}

void *send_to_remote(void *v_instruction) {
    struct instruction *instruction = (struct instruction *)v_instruction;
    int result;

    result = connect_to_host(instruction);
    if (result == 0) {
        ssh_channel channel = set_up_ssh_channel(instruction);
        if (channel == NULL) {
            result = -1;
        }
        else {
            result = transfer_data(instruction, channel);

            ssh_channel_close(channel);
            ssh_channel_free(channel);
        }

        ssh_disconnect(instruction->session);
    }

    close(instruction->fd);
    ssh_free(instruction->session);

    return result == 0 ? (void *)1 : NULL;
}

int client_mode(void) {
    struct stat stat;
    struct instruction instructions[config.threads];
    pthread_t threads[config.threads];

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();

    int fd = instructions[0].fd = open(config.input_filename, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "could not open file '%s': ", config.input_filename);
        perror("");
        return 1;
    }

    if (fstat(fd, &stat) == -1) {
        fprintf(stderr, "could not fstat file '%s': ", config.input_filename);
        perror("");
        return 1;
    }

    int thread_count = stat.st_size < MIN_THREADED_COPY_SIZE ? 1 : config.threads;

    for (int thread = 1; thread < thread_count; thread++) {
        instructions[thread].fd = open(config.input_filename, O_RDONLY);
        if (instructions[thread].fd == -1) {
            fprintf(stderr, "could not open file '%s': ", config.input_filename);
            perror("");
            return 1;
        }
    }

    size_t chunk_size = stat.st_size / thread_count;
    for (int thread = 0; thread < thread_count; thread++) {
        struct instruction *instruction = &instructions[thread];

        instruction->session = ssh_new();
        ssh_options_copy(config.ssh_opts, &instruction->session);
        instruction->offset = chunk_size * thread;
        instruction->size = thread == thread_count - 1 ? stat.st_size - (thread * chunk_size) : chunk_size;

        if (pthread_create(&threads[thread], NULL, send_to_remote, (void *)instruction) == -1) {
            fprintf(stderr, "couldn't create threads, aborting\n");
            abort();
        }
    }

    void *value;
    int result = 0;

    for (int thread = 0; thread < thread_count; thread++) {
        if (pthread_join(threads[thread], &value) != 0) {
            fprintf(stderr, "couldn't join thread, aborting\n");
            abort();
        }
        if (value == NULL) {
            result = 1; // failed
        }
    }

    return result;
}

int server_mode(void) {
    size_t size = config.file_size;

    int fd = open(config.input_filename, O_WRONLY|O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    if (lseek(fd, config.file_offset, SEEK_SET) == -1) {
        perror("lseek");
        return 1;
    }

    char *buffer = (char *)malloc(BLOCK_SIZE);
    if (buffer == NULL) abort();

    ssize_t n;
    while (size > 0) {
        n = read(0, buffer, size < BLOCK_SIZE ? size : BLOCK_SIZE);
        if (n <= 0) abort(); // TODO
        if (write(fd, buffer, n) != n) abort(); // TODO
        size -= n;
    }

    free(buffer);

    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    assert(MIN_THREADED_COPY_SIZE > MAX_THREADS);

    int result;

    result = load_config(argc, argv);
    if (result == -1) return 1;

    result = config.server_mode ? server_mode() : client_mode();

    ssh_free(config.ssh_opts);
    return result;
}

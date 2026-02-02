#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <time.h>
#include <virtfuzz.h>

/**
 * Generate a sequence of n bytes filled with random data
 * @param buffer Pointer to the buffer to fill
 * @param n Number of bytes to generate
 */
void generate_random_bytes(uint8_t *buffer, size_t n) {
    static int initialized = 0;

    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }

    for (size_t i = 0; i < n; i++) {
        buffer[i] = (uint8_t)(rand() % 256);
    }
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -f <device_model_file> -n <device_name>\n", prog_name);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -f, --file <path>    Path to device model file (required)\n");
    fprintf(stderr, "  -n, --name <name>    Device model name (required)\n");
    fprintf(stderr, "  -h, --help           Display this help message\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s -f config/dbm/e1000.json -n e1000\n", prog_name);
}

int main(int argc, char *argv[]) {
    const char *device_model_file = NULL;
    const char *device_name = NULL;
    int opt;
    int re;

    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"name", required_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    // Parse command line arguments
    while ((opt = getopt_long(argc, argv, "f:n:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f':
                device_model_file = optarg;
                break;
            case 'n':
                device_name = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Validate required arguments
    if (device_model_file == NULL || device_name == NULL) {
        if (device_model_file == NULL) {
            fprintf(stderr, "Error: Device model file is required\n");
        }
        if (device_name == NULL) {
            fprintf(stderr, "Error: Device name is required\n");
        }
        fprintf(stderr, "\n");
        print_usage(argv[0]);
        return 1;
    }

    // Display configuration
    printf("Device Model File: %s\n", device_model_file);
    printf("Device Name: %s\n", device_name);

    // Initialize device model
    re = init_device_model(device_model_file);
    assert(re != -1);
    if (re == 1) {
        fprintf(stderr, "Error: device_model_file '%s' does not exist!\n", device_model_file);
        return 1;
    }

    printf("Device model initialized successfully\n");

    // Initialize three interfaces
    add_interface(INTERFACE_TYPE_MMIO, 0xFFFF0000, 0x1000, "mmio-00", 1, 4);
    add_interface(INTERFACE_TYPE_MMIO, 0xFFFF1000, 0x1000, "mmio-01", 1, 4);
    add_interface(INTERFACE_TYPE_MMIO, 0xFFFF2000, 0x1000, "mmio-02", 1, 4);
    add_interface( INTERFACE_TYPE_DMA, 0x00000000, 0x0001,  "dma-00", 0, 0);

    // Print available interfaces
    printf("\nAvailable interfaces:\n");
    print_interfaces();

    MessageSequence message_sequence;
    uint8_t Data[4096];
    generate_random_bytes(Data, 4096);
    size_t num_messages = get_message_sequence(Data, 4096, &message_sequence);
    printf("\n[FUZZ] num_messages: %ld.\n", num_messages);

    for (size_t i = 0; i < num_messages; ++i) {
        // messageToReadableString(&message_sequence.messages[i]);
    }
    cleanup(&message_sequence);

    return 0;
}
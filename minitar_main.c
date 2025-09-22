#include <stdio.h>
#include <string.h>

#include "file_list.h"
#include "minitar.h"

// Prints list of files in a file list
static void file_list_print(const file_list_t *lst) {
    for (node_t *n = lst->head; n; n = n->next) {
        if (n->name)
            puts(n->name);
    }
}

// Print usage message
void print_usage(const char *progname) {
    printf("Usage: %s -c|a|t|u|x -f ARCHIVE [FILE...]\n", progname);
}

int main(int argc, char **argv) {
    // Command-line argument validation
    if (argc < 4) {
        print_usage(argv[0]);
        return 0;
    }

    // Initialize file list
    file_list_t files;
    file_list_init(&files);

    // TODO: Parse command-line arguments and invoke functions from 'minitar.h'
    // to execute archive operations

    // Command-line argument parsing
    const char *op = argv[1];
    if (strcmp(argv[2], "-f") != 0) {
        print_usage(argv[0]);
        return 1;
    }
    const char *archive = argv[3];

    // Validate operation and file arguments
    int needs_files = (strcmp(op, "-c") == 0) || (strcmp(op, "-a") == 0) || (strcmp(op, "-u") == 0);
    int no_files = (strcmp(op, "-t") == 0) || (strcmp(op, "-x") == 0);

    // Check for correct number of arguments based on operation
    if (needs_files && argc < 5) {
        print_usage(argv[0]);
        return 1;
    }

    // Extra arguments provided for operations that don't need them
    if (no_files && argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    // Populate file list if needed
    for (int i = 4; i < argc; i++) {
        if (file_list_add(&files, argv[i]) != 0) {
            perror("Error: failed to add file to list");
            file_list_clear(&files);
            return 1;
        }
    }

    int rc = 0;

    // Create, append, list, update, or extract files from archive
    if (strcmp(op, "-c") == 0) {
        rc = create_archive(archive, &files);
        if (rc != 0) {
            file_list_clear(&files);
            return 1;
        }

        // Append files to archive
    } else if (strcmp(op, "-a") == 0) {
        rc = append_files_to_archive(archive, &files);
        if (rc != 0) {
            file_list_clear(&files);
            return 1;
        }

        // List files in archive
    } else if (strcmp(op, "-t") == 0) {
        file_list_t names;
        file_list_init(&names);
        rc = get_archive_file_list(archive, &names);
        if (rc != 0) {
            file_list_clear(&names);
            file_list_clear(&files);
            return 1;
        }
        file_list_print(&names);
        file_list_clear(&names);

        // Update files in archive
    } else if (strcmp(op, "-u") == 0) {
        // Verify all requested files are already in archive
        file_list_t names;
        file_list_init(&names);
        rc = get_archive_file_list(archive, &names);
        if (rc != 0) {
            file_list_clear(&names);
            file_list_clear(&files);
            return 1;
        }
        // Check if all files to be updated are present in the archive
        int missing = 0;
        for (node_t *n = files.head; n; n = n->next) {
            if (!file_list_contains(&names, n->name)) {
                missing = 1;
                break;
            }
        }
        file_list_clear(&names);
        if (missing) {
            fprintf(
                stderr,
                "Error: One or more of the specified files is not already present in archive\n");
            file_list_clear(&files);
            return 1;
        }
        rc = append_files_to_archive(archive, &files);
        if (rc != 0) {
            file_list_clear(&files);
            return 1;
        }

        // Extract files from archive
    } else if (strcmp(op, "-x") == 0) {
        rc = extract_files_from_archive(archive);
        if (rc != 0) {
            file_list_clear(&files);
            return 1;
        }
        // Invalid operation
    } else {
        print_usage(argv[0]);
        file_list_clear(&files);
        return 1;
    }

    // Clean up and exit
    file_list_clear(&files);
    return 0;
}

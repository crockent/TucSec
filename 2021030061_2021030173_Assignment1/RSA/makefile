# Define the compiler and flags
CC = gcc
LDFLAGS = -g -lgmp          # Libraries to link

# Define the target executable
TARGET = rsa_assign_1

# List all source files
SRCS = rsa_source.c

# Default rule: build the program
all: $(TARGET)

# Rule to create the executable
$(TARGET): $(SRCS)
	$(CC) -o $(TARGET) $(SRCS) $(LDFLAGS)

# Clean rule to remove the build files
clean:
	rm -f $(TARGET)

# Phony targets to prevent conflicts with files named 'all' or 'clean'
.PHONY: all clean

CC = gcc
CFLAGS = -Wall -O2
TARGET = nattype
SRC = src/nat-type.c
BUILD_DIR = build

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -o $@ $(SRC)

run: $(BUILD_DIR)/$(TARGET)
	@./$(BUILD_DIR)/$(TARGET)

clean:
	@rm -rf $(BUILD_DIR)

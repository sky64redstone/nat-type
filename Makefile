CC = gcc
CFLAGS = -Wall -O2
TARGET = nat_detect
SRC = nat_detect.c
BUILD_DIR = build

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -o $@ $(SRC)

run: $(BUILD_DIR)/$(TARGET)
	@./$(BUILD_DIR)/$(TARGET)

clean:
	@rm -rf $(BUILD_DIR)

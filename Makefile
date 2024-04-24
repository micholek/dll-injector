OUTPUT_DIR = output
TARGET = $(OUTPUT_DIR)/injector.exe

.PHONY: build
build: $(TARGET)

$(TARGET): main.cpp
	cl main.cpp /nologo /std:c++latest /EHsc /Zi /W4 /Fe$(TARGET) /Fd$(OUTPUT_DIR)/ /Fo$(OUTPUT_DIR)/

.PHONY: clean
clean:
	del /q $(OUTPUT_DIR)

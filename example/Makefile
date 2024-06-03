OUTPUT_DIR = output
TARGET = $(OUTPUT_DIR)/injector.exe

.PHONY: build
build: $(TARGET)

$(TARGET): example.cpp ../src/injector.cpp ../include/injector/injector.h
	cl example.cpp ../src/injector.cpp /nologo /std:c++latest /EHsc /Zi /W4 /I../include /Fe$(TARGET) /Fd$(OUTPUT_DIR)/ /Fo$(OUTPUT_DIR)/

.PHONY: clean
clean:
	del /q $(OUTPUT_DIR)

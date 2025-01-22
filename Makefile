.PHONY: all run

all: tidy generate build run


tidy:
	@echo "整理go依赖包:"
	go mod tidy

generate:
	@echo "生成BPF依赖的go文件:"
	go generate

build:
	@echo "构建go项目，生成ELF文件:"
	CGO_ENABLED=0 GOARCH=amd64 go build


clean:
	@echo "清理go项目："
	sudo rm -f bpf_bpfeb.go bpf_bpfel.go bpf_bpfeb.o bpf_bpfel.o
	go clean -cache

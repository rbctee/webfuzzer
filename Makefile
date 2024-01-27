.DEFAULT_GOAL := build

out_dir:
	if [ ! -d out ]; then mkdir out; fi

build: out_dir
	go build -o out

clean: out_dir
	if [ -e out/webfuzzer ]; then rm out/webfuzzer; fi

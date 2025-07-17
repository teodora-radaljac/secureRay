.PHONY: all head verification worker clean
all: dirs head verification worker

dirs:
	mkdir -p head verification worker
head: dirs
	cd head && go build -o ../head_exec head.go

verification: dirs
	cd verification && go build -o ../verification_exec verification.go

worker: dirs
	cd worker && go build -o ../worker_exec worker.go

clean: dirs
	rm -f head_exec verification_exec worker_exec


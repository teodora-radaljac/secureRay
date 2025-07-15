.PHONY: all head verification worker clean
all: head verification worker

head:
	cd head && go build -o ../head_exec head.go

verification:
	cd verification && go build -o ../verification_exec verification.go

worker:
	cd worker && go build -o ../worker_exec worker.go

clean:
	rm -f head_exec verification_exec worker_exec


LIMA_OPTS := --set='.cpus = 2 | .memory = "2GiB" '

list: 
	limactl list
ls-templates:
	limactl start --list-templates

run:
	limactl start $(LIMA_OPTS) --name owasp-benchmark template://docker --tty=false 

start:
	limactl start owasp-benchmark 

stop:
	limactl stop owasp-benchmark -f

run-benchmark: start
	limactl shell owasp-benchmark /bin/bash -c "bash init.sh && cd ~/ && git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git >/dev/null 2>&1 ; cd ~/BenchmarkJava && bash runBenchmark.sh"

rm: stop
	limactl delete owasp-benchmark 
shell:
	limactl shell owasp-benchmark
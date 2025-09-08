CFLAGS = -Wall -Werror -g
CC = gcc $(CFLAGS)
SHELL = /bin/bash
CWD = $(shell pwd | sed 's/.*\///g')
AN = proj1

TEST_FILES = f1.bin \
	f1.txt \
	f2.bin \
	f2.txt \
	f3.bin \
	f3.txt \
	f4.bin \
	f4.txt \
	f5.bin \
	f5.txt \
	f6.bin \
	f6.txt \
	f7.bin \
	f7.txt \
	f8.bin \
	f8.txt \
	f9.bin \
	f9.txt \
	f10.bin \
	f10.txt \
	f11.bin \
	f11.txt \
	f12.bin \
	f12.txt \
	f13.bin \
	f13.txt \
	f14.bin \
	f14.txt \
	f15.bin \
	f15.txt \
	f16.bin \
	f16.txt \
	f17.bin \
	f17.txt \
	f17.bin \
	f17.txt \
	f18.bin \
	f18.txt \
	f19.bin \
	f19.txt \
	f20.bin \
	f20.txt \
	gatsby.txt \
	hello.txt \
	large.bin

minitar: minitar_main.c file_list.o minitar.o
	$(CC) -o $@ $^ -lm

file_list.o: file_list.c file_list.h
	$(CC) -c $<

minitar.o: minitar.c minitar.h
	$(CC) -c $<

test-setup:
	@chmod u+x testius

ifdef testnum
test: minitar test-setup
	./testius test_cases/tests.json -v -n "$(testnum)"
else
test: minitar test-setup
	./testius test_cases/tests.json
endif

clean:
	rm -f *.o minitar

clean-tests:
	rm -f $(TEST_FILES)
	rm -rf test_results test_files test.tar

zip: clean clean-tests
	rm -f proj1-code.zip
	cd .. && zip "$(CWD)/$(AN)-code.zip" -r "$(CWD)" -x "$(CWD)/test_cases/*" "$(CWD)/testius"
	@echo Zip created in $(AN)-code.zip
	@if (( $$(stat -c '%s' $(AN)-code.zip) > 10*(2**20) )); then echo "WARNING: $(AN)-code.zip seems REALLY big, check there are no abnormally large test files"; du -h $(AN)-code.zip; fi
	@if (( $$(unzip -t $(AN)-code.zip | wc -l) > 256 )); then echo "WARNING: $(AN)-code.zip has 256 or more files in it which may cause submission problems"; fi

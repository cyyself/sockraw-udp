test: sender receiver
	./sender
	./receiver
sender: sender.c
	gcc sender.c -o sender
receiver: receiver.c
	gcc receiver.c -o receiver
clean:
	rm 1.bin
	rm sender
	rm receiver

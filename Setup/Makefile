
default: firewallSetup

firewallSetup.o: firewallSetup.c $(HEADERS)
	gcc -c firewallSetup.c -o firewallSetup.o

firewallSetup: firewallSetup.o
	gcc firewallSetup.o -o firewallSetup

clean:
	-rm -f firewallSetup.o
	-rm -f firewallSetup

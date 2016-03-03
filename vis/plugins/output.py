from termcolor import colored, cprint
import threading

def print_info(msg):
	lock = threading.Lock()
	lock.acquire()
	print ""
	print colored("[", "blue") +colored("*", "yellow") +colored("]", "blue") +" %s" %msg
	print ""
	lock.release()

def print_success(msg):
	lock = threading.Lock()
	lock.acquire()
	print ""
	print colored("[", "blue") +colored("+", "green") +colored("]", "blue") +" %s" %msg
	print ""
	lock.release()

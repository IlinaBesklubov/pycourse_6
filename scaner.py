import datetime
import netaddr
from scapy.all import *
from scapy_http import http
import threading
from tkinter import *
import re

# глобальные определения
FOREGROUND_COLOR = "#cccccc"
BACKGROUND_COLOR = "#2d2d2d"
SELECTION_COLOR = "#373b41"
LISTBOX_BACKGROUND_COLOR = "#292929"
IP_RANGE = "192.168.239.0/24"

# регулярные выраыжения для проверки входных данных
IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
PORT_RANGE_REGEX = "^[0-9]+-[0-9]+$"

'''

Структура классов сканеров:
	init - инициализация классса
	show - отобразить виджеты сканера в главном окне
	hide - скрыть виждеты сканера с главного окна
	do_scan - функция сканирования
	scan - запуск функции do_scan в отдельном потоке
	scan_stop - остановка сканирования

'''


# базовый класс для сканеров сети
class BASE_NET_SCANNER:
	# формы сканера отображены в окне
	isActive = False
	# класс проинициализирован
	isInitiated = False
	# сканирование идет
	isScanning = False
	log_title = "Base log title"
	res_title = "Base result title"

	# инициализация элементов
	def init(self, root_view):
		self.root_view = root_view

		if not self.isInitiated:
			self.log_lframe = LabelFrame(root_view, text=self.log_title, background=BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR) 
			self.log_listbox = Listbox(self.log_lframe, background=LISTBOX_BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR, highlightbackground=FOREGROUND_COLOR)
			self.res_lframe = LabelFrame(root_view, text=self.res_title, background=BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR)
			self.res_listbox = Listbox(self.res_lframe, background=LISTBOX_BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR)
			self.isInitiated = True

	# отобразить элементы на форме
	def show(self):
		if not self.isActive and self.isInitiated:
			self.log_lframe.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.log_listbox.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)

			self.res_lframe.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.res_listbox.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.isActive = True

	# скрыть элементы
	def hide(self):
		if self.isActive and self.isInitiated:
			self.log_lframe.pack_forget()
			self.log_listbox.pack_forget()

			self.res_lframe.pack_forget()
			self.res_listbox.pack_forget()
			self.isActive = False

	# функция сканирования
	def do_scan(self):
		pass

	# запуск сканирования в отдельном потоке
	def scan(self):
		if not self.isScanning:
			self.isScanning = True
			scan_thread = threading.Thread(target=self.do_scan)
			scan_thread.start()


	# остановить сканирование
	def scan_stop(self):
		self.isScanning = False
	

	def __init__(self, root_view):
		self.init(root_view)

# ARP сканер
class ARP_SCANNER(BASE_NET_SCANNER):
	log_title = "ARP log process:"
	res_title = "ARP results:"

	def do_scan(self):
		global status_bar

		# установить статус
		set_status("ARP scanning..")

		# очистить поле результатов
		self.res_listbox.delete(0, END)

		self.log_listbox.insert(END, "[*] Start scanning")

		# засечь время сканирования
		scan_time = datetime.now()

		conf.verb = 0

		# scapy фукнция для отправки и приема пакетов
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP_RANGE), timeout = 2, inter=0.1)

		# вывести результаты в окна
		for snd, rcv in ans:
			self.log_listbox.insert(END, "found " + rcv.sprintf(r"%ARP.psrc%"))

		for snd, rcv in ans:
			self.arp_res_listbox.insert(END, rcv.sprintf(r"%ARP.psrc% has %Ether.src%"))

		scan_time = datetime.now() - scan_time

		self.log_listbox.insert(END, "[*] Scan Complete")
		self.log_listbox.insert(END, "[*] Scan Duration: %s" % (scan_time))

		self.isScanning = False

		set_status("idle")

# ICMP сканер
class ICMP_SCANNER(BASE_NET_SCANNER):
	log_title = "ICMP log process:"
	res_title = "ICMP results:"

	def do_scan(self):
		global status_bar

		# установить статус
		set_status("ICMP scanning..")

		self.log_listbox.insert(END, "[*] Start scanning")
		scan_time = datetime.now()

		addresses = netaddr.IPNetwork(IP_RANGE)
		live_counter = 0

		for host in addresses:

			# проверка, нажата ли кнопка об остановке сканирования
			if not self.isScanning:
				break

			if host == addresses.network or host == addresses.broadcast:
				continue
		 
			resp = sr1(IP(dst=str(host))/ICMP(), timeout=2, verbose=0)
		 
			if resp is None:
				# хост не отвечает
				self.log_listbox.insert(END, str(host) + " is down or not responding")

			elif int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
				# хост блокирует ICMP
				self.log_listbox.insert(END, host + "is blocking ICMP")

			else:
				# хост активен
				self.log_listbox.insert(END, str(host) + " is responding")
				self.res_listbox.insert(END, str(host) + " is responding")

				live_counter += 1

		self.log_listbox.insert(END, "%d of %d hosts are online" % (live_counter, addresses.size))

		scan_time = datetime.now() - scan_time

		self.log_listbox.insert(END, "[*] Scan Complete")
		self.log_listbox.insert(END, "[*] Scan Duration: %s" % (scan_time))

		self.isScanning = False
 
		set_status("idle")


class HTTP_MONITOR:
	isActive = False
	isInitiated = False
	isScanning = False

	# инициализация сниффера
	def init(self, root_view):
		self.root_view = root_view

		if not self.isInitiated:
			self.http_res_lframe = LabelFrame(root_view, text="HTTP monitoring:", background=BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR)
			self.http_res_listbox = Listbox(self.http_res_lframe, background=LISTBOX_BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR)
			self.isInitiated = True

	# отобразить формы сниффера
	def show(self):
		if not self.isActive and self.isInitiated:
			self.http_res_lframe.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.http_res_listbox.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.isActive = True

	# функция обработки пакета
	def process_tcp_packet(self, packet):
		if not packet.haslayer(http.HTTPRequest):
			return

		http_layer = packet.getlayer(http.HTTPRequest)
		ip_layer = packet.getlayer(IP)

		self.http_res_listbox.insert(END, "HTTP %s: %s requests %s%s" % (http_layer.fields["Method"].decode("utf-8"), ip_layer.fields["src"], http_layer.fields["Host"].decode("utf-8"), http_layer.fields["Path"].decode("utf-8")))

	# остановка сниффера
	def stop_sniff_cond(self, packet):
		return not self.isScanning


	def hide(self):
		if self.isActive and self.isInitiated:
			self.http_res_lframe.pack_forget()
			self.http_res_listbox.pack_forget()
			self.isActive = False


	def do_scan(self):
		global status_bar

		set_status("HTTP monitoring..")

		# запустить сниффинг
		sniff(filter='tcp', prn=self.process_tcp_packet, stop_filter=self.stop_sniff_cond)

		set_status("idle")


	def scan(self):
		if not self.isScanning:
			self.isScanning = True
			http_monitor_thread = threading.Thread(target=self.do_scan)
			http_monitor_thread.start()


	def scan_stop(self):
		self.isScanning = False


	def __init__(self, root_view):
		self.init(root_view)

# TCP сканер портов
class TCP_PORT_SCANNER:
	isActive = False
	isInitiated = False
	isScanning = False
	log_title = "Port scan log:"
	res_title = "Found ports:"


	def init(self, root_view):
		self.root_view = root_view

		if not self.isInitiated:
			self.top_frame = Frame(root_view, background=BACKGROUND_COLOR)
			self.bottom_frame = Frame(root_view, background=BACKGROUND_COLOR)

			self.log_lframe = LabelFrame(self.top_frame, text=self.log_title, background=BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR) 
			self.log_listbox = Listbox(self.log_lframe, background=LISTBOX_BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR, highlightbackground=FOREGROUND_COLOR)
			self.res_lframe = LabelFrame(self.top_frame, text=self.res_title, background=BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR)
			self.res_listbox = Listbox(self.res_lframe, background=LISTBOX_BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR)
			self.enter_ip_label = Label(self.bottom_frame, background=BACKGROUND_COLOR, bd=0, foreground=FOREGROUND_COLOR, text="Enter IP and port range to scan:")
			self.enter_ip_entry = Entry(self.bottom_frame, background=SELECTION_COLOR, bd=2, foreground=FOREGROUND_COLOR, justify="center", width=40)
			self.enter_ip_port_range = Entry(self.bottom_frame, background=SELECTION_COLOR, bd=2, foreground=FOREGROUND_COLOR, justify="center")
			self.scan_button = Button(text="Scan", background=SELECTION_COLOR, bd=2, foreground=FOREGROUND_COLOR, command=tcp_port_scan)

			self.enter_ip_port_range.insert(0, "0-1024")

			self.isInitiated = True


	def show(self):
		if not self.isActive and self.isInitiated:
			self.top_frame.pack(side=TOP, fill=BOTH, expand=TRUE)
			self.bottom_frame.pack(side=BOTTOM, fill=BOTH, expand=TRUE)


			self.log_lframe.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.log_listbox.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)

			self.res_lframe.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)
			self.res_listbox.pack(side=LEFT, fill=BOTH, padx=5, pady=5, expand=True)

			self.scan_button.pack(side=BOTTOM, anchor=CENTER, expand=True)
			self.enter_ip_port_range.pack(side=BOTTOM, anchor=CENTER, expand=True)
			self.enter_ip_entry.pack(side=BOTTOM, anchor=CENTER, expand=True)
			self.enter_ip_label.pack(side=BOTTOM, anchor=CENTER, expand=True)

			self.isActive = True


	def hide(self):
		if self.isActive and self.isInitiated:
			self.top_frame.pack_forget()
			self.bottom_frame.pack_forget()

			self.log_lframe.pack_forget()
			self.log_listbox.pack_forget()

			self.res_lframe.pack_forget()
			self.res_listbox.pack_forget()

			self.scan_button.pack_forget()
			self.enter_ip_port_range.pack_forget()
			self.enter_ip_entry.pack_forget()
			self.enter_ip_label.pack_forget()
			self.isActive = False

	# функция сканирования
	def do_scan(self, port_range, ip):
		global status_bar

		set_status("TCP port scanning..")

		src_port = RandShort()

		self.log_listbox.delete(0, END)
		self.res_listbox.delete(0, END)
		self.log_listbox.insert(END, "[*] Start scanning")

		for dst_port in port_range:

			if not self.isScanning:
				break

			tcp_connect_scan_resp = sr1(IP(dst=ip)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=10)

			if tcp_connect_scan_resp == None:
				self.log_listbox.insert(END, "port " + str(dst_port) + " is closed")

			elif tcp_connect_scan_resp.haslayer(TCP):
				if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:
					send_rst = sr(IP(dst=ip)/TCP(sport=src_port, dport=dst_port, flags="AR"), timeout=10)
					self.log_listbox.insert(END, "port " + dst_port + " open")
					self.res_listbox.insert(END, dst_port)

				elif tcp_connect_scan_resp.getlayer(TCP).flags == 0x14:
					self.log_listbox.insert(END, "port " + str(dst_port) + " is closed")

		set_status("idle")


	def scan(self, ip, port_range):
		if not self.isScanning:
			self.isScanning = True
			scan_thread = threading.Thread(target=self.do_scan, args=(port_range, ip))
			scan_thread.start()


	def scan_stop(self):
		self.isScanning = False
		

	def __init__(self, root_view):
		self.init(root_view)


root = 0
scan_view = 0

arp_scanner = 0
icmp_scanner = 0
http_monitor = 0
tcp_port_scanner = 0
status_bar = 0

# установка строки статуса
def set_status(_text):
	global status_bar

	status_bar.config(text=_text)

# коллбеки кнопок старта и завершения сканирования 

def arp_scan():
	global arp_scanner

	arp_show()
	arp_scanner.scan()

# функции вида *_show() - скрыть формы других классов и отобразить формы текущего класса

def arp_show():
	global arp_scanner
	global icmp_scanner
	global http_monitor
	global tcp_port_scanner

	if not arp_scanner.isActive:
		if icmp_scanner.isActive:
			icmp_scanner.hide()
		if http_monitor.isActive:
			http_monitor.hide()
		if tcp_port_scanner.isActive:
			tcp_port_scanner.hide()

		arp_scanner.show()


def arp_scan_stop():
	global arp_scanner
	arp_scanner.scan_stop()

def icmp_scan():

	global icmp_scanner

	icmp_show()
	icmp_scanner.scan()


def icmp_show():

	global arp_scanner
	global icmp_scanner
	global http_monitor
	global tcp_port_scanner

	if not icmp_scanner.isActive:
		if arp_scanner.isActive:
			arp_scanner.hide()
		if http_monitor.isActive:
			http_monitor.hide()
		if tcp_port_scanner.isActive:
			tcp_port_scanner.hide()

		icmp_scanner.show()

def icmp_scan_stop():
	global icmp_scanner
	icmp_scanner.scan_stop()


def http_monitor():

	global http_monitor

	http_show()
	http_monitor.scan()


def http_show():

	global arp_scanner
	global icmp_scanner
	global http_monitor
	global tcp_port_scanner

	if not http_monitor.isActive:
		if arp_scanner.isActive:
			arp_scanner.hide()
		if icmp_scanner.isActive:
			icmp_scanner.hide()
		if tcp_port_scanner.isActive:
			tcp_port_scanner.hide()

		http_monitor.show()


def http_monitor_stop():
	global http_monitor
	http_monitor.scan_stop()


def tcp_port_show():

	global arp_scanner
	global icmp_scanner
	global http_monitor
	global tcp_port_scanner

	if not tcp_port_scanner.isActive:
		if arp_scanner.isActive:
			arp_scanner.hide()
		if http_monitor.isActive:
			http_monitor.hide()
		if icmp_scanner.isActive:
			icmp_scanner.hide()

		tcp_port_scanner.show()



def tcp_port_scan():
	global tcp_port_scanner
	ip = tcp_port_scanner.enter_ip_entry.get()
	port_range = tcp_port_scanner.enter_ip_port_range.get()

	if re.match(PORT_RANGE_REGEX, port_range) and re.match(IP_REGEX, ip):
		port_range = port_range.split('-')

		tcp_port_show()
		tcp_port_scanner.scan(ip, range(int(port_range[0]), int(port_range[1])))
	
	else:
		set_status("incorrect input")


def tcp_port_stop():
	global tcp_port_scanner

	tcp_port_scanner.isScanning = False


# основная инициализация формы
root = Tk()

root.title("Net scanner")
root.minsize(800,500)

root.configure(background=BACKGROUND_COLOR)

# инифиализация меню
main_menu = Menu(root)

arp_menu = Menu(main_menu, tearoff=0)
arp_menu.add_command(label="Show ARP view", command=arp_show)
arp_menu.add_command(label="Scan", command=arp_scan)
arp_menu.add_command(label="Stop", command=arp_scan_stop)

icmp_menu = Menu(main_menu, tearoff=0)
icmp_menu.add_command(label="Show ICMP view", command=icmp_show)
icmp_menu.add_command(label="Scan", command=icmp_scan)
icmp_menu.add_command(label="Stop", command=icmp_scan_stop)

http_menu = Menu(main_menu, tearoff=0)
http_menu.add_command(label="Show HTTP view", command=http_show)
http_menu.add_command(label="Scan", command=http_monitor)
http_menu.add_command(label="Stop", command=http_monitor_stop)

port_scan_menu = Menu(main_menu, tearoff=0)
port_scan_menu.add_command(label="TCP port scan", command=tcp_port_show)
port_scan_menu.add_command(label="Stop port scan", command=tcp_port_stop)

main_menu.add_cascade(label="ARP scan", menu=arp_menu)
main_menu.add_cascade(label="ICMP scan", menu=icmp_menu)
main_menu.add_cascade(label="HTTP monitor", menu=http_menu)
main_menu.add_cascade(label="Port scan", menu=port_scan_menu)

root.config(menu=main_menu)

root.update()

# инициализация фрейма, в котором помещаются окна сканеров
scan_view = Frame(root, width=root.winfo_width(), height=int(root.winfo_height() * 0.98), background=BACKGROUND_COLOR)
scan_view.pack(expand=True, padx=5, pady=5, fill=BOTH)

# инициализация строки статуса
status_bar = Label(root, text="idle", background=BACKGROUND_COLOR, foreground=FOREGROUND_COLOR)
status_bar.pack(side=BOTTOM, anchor=SW, expand=True, padx=5, pady=5)

# инициализация классов сканеров
arp_scanner = ARP_SCANNER(scan_view)
icmp_scanner = ICMP_SCANNER(scan_view)
http_monitor = HTTP_MONITOR(scan_view)
tcp_port_scanner = TCP_PORT_SCANNER(scan_view)

root.mainloop()
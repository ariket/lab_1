#!/usr/bin/env python
"""laboration1.py"""
#This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola

# Assignment(in swedish):
# Skriv ett eget verktyg som använder nmap för att skanna ip adresser.

# Krav:
# Möjlighet att spara resultatet av skanningen till fil (.txt)
# Använd input/fil för att bestämma vilka ip-adresser som ska skannas
# Programmet ska ha en meny där användaren kan välja vad som ska göras.

# Använd din fantasi för att skapa fler funktioner i verktyget.
import os
import ipaddress
import nmap

exit_command = {"9", "x", "X", "z", "Z", "q", "Q"}


def ip_address_validator(ip):
    """ Check if legal IP address """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def file_list():
    """ Lists all .txt files in current directory """
    file_index_name = {}
    index = 1
    for file in os.listdir():
        if file.endswith(".txt"):
            print(f"{index} - {file}")
            file_index_name[f"{index}"] = f"{file}"
            index += 1
    return file_index_name


def select_file():
    """ Select a .txt file in current directory """
    file_index_name = file_list()
    print("Select file by number:")
    while True:
        try:
            selected_file = int(input(">>> "))
        except ValueError:
            print(f"Select file by number 1 - {len(file_index_name)}.")
        else:
            if selected_file <= len(file_index_name):
                return file_index_name[f"{selected_file}"]
            print(f"Select file by number 1 - {len(file_index_name)}.")


def read_file(filename):
    """Read a .txt file and print to command line"""
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.readlines()
            print("*******************************************************")
            for line in content:
                print(line.strip())
    else:
        print(f"File doesn`t exist: {filename}")


def run_nmap_original():
    """ Calls original nmap with flags"""
    print("Be careful, no error check of your input")
    ip = input("Enter IP address you want to scan.\n>>> ")  #ip = "45.33.32.156"
    flags = input("Enter Nmap flags you want to use in this scan.\n"
                 +"For example: -A -T4 (aggresive scan).\n>>> ")

    response = os.popen(f"nmap {flags} {ip}")   #response = os.popen(f"nmap -A -T4 {ip}")
    for line in response:
        print(line.rstrip("\n"))


def run_nmap(options):
    """ Calls python-nmap with flags"""
    def run_nmap_menu():
        print("*******************************************************")
        print("*  1 - Get <IP> addresses from file                   *")
        print("*  2 - Get <IP> address from command prompt           *")
        print("*  9 - Go back to main menu                           *")
        print("*******************************************************")

    def create_file():
        print('Enter filename of the new file you want to create.')
        while True:
            new_file = input(">>> ")
            if new_file == "":
                print("You must specify a new non existing filename.")
            elif not os.path.exists(new_file):
                with open(new_file, 'x', encoding='utf-8') as file:
                    print(f"File created: {file}.")
                return new_file
            else:
                print(f"{new_file} already exists.")
                print("You must specify a new non existing filename.")

    def save_to_file():
        print(f"Do want to save scan to existing file in {os.getcwd()}? (Y/N)")
        while True:
            command = input(">>> ").lower()
            if command == "y":
                return select_file()
            if command == "n":
                return create_file()
            print(f"Invalid command: '{command}'.")

    def input_ip():
        print("Fill in IP address you want to scan:")
        while True:
            try:
                ip_address_to_use = ipaddress.ip_address(input(">>> "))
            except ValueError:
                print("Error, not a valid IP address.")
            else:
                return ip_address_to_use

    def nmap_start(ip_address, save_scan_to_file, options):
        target = str(ip_address) #ip_address, test IP: "45.33.32.156"
        print(f"Scanning {target.rstrip(chr(10))}.....Standby")
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments=options)
        # print(scanner.command_line()) #print(scanner.csv())
        printdata = ''
        for host in scanner.all_hosts():
            print('--------------------------------------------------------')
            printdata += f"Host: {host} ({scanner[host].hostname()})"
            printdata += f" State: {scanner[host].state()}\n"
            for proto in scanner[host].all_protocols():
                printdata += f"Protocol: {proto}" + chr(10)
                ports = scanner[host][proto].keys()
                for port in ports:
                    printdata += f"Port: {port}, State: {scanner[host][proto][port]['state']}, "
                    printdata += f"Name: {scanner[host][proto][port] ['name']}, Version: "
                    printdata += f"{scanner[host][proto][port]['version']}\n"
        printdata += '--------------------------------------------------------'
        if save_scan_to_file:
            with open(save_scan_to_file, "a", encoding='utf-8') as file_save:
                file_save.write(printdata + chr(10))
        print(printdata)

    def nmap_scan(ip_address_file, ip_address):
        print("Do you want to save scan to file? (Y/N)")
        while True:
            save_scan_to_file = None
            command = input(">>> ").lower()
            if command == "y":
                save_scan_to_file = save_to_file()
                if save_scan_to_file != ip_address_file:
                    break
                print(f"Cannot use <{ip_address_file}> to save scan," +
                      " it's already used to get IP data.")
                print("Do you really want to save scan to file? (Y/N)")
            elif command == "n":
                break
            else:
                print(f"Invalid command: '{command}'.")
        print('--------------------------------------------------------')
        print('|                Nmap scan starts                      |')
        print('--------------------------------------------------------')
        if ip_address:
            nmap_start(ip_address, save_scan_to_file, options)
        else:
            with open(ip_address_file, "r", encoding='utf-8') as data:
                for ip_adress in data:
                    if ip_address_validator(ip_adress.rstrip('\n')):
                        nmap_start(ip_adress, save_scan_to_file, options)
                    else:
                        print(f"Not a vaild IP: {ip_adress.rstrip(chr(10))} , skipping this line")
                        print('--------------------------------------------------------')
    while True:
        run_nmap_menu()
        command = input(">>> ")
        if command == "1":
            ip_address_file = select_file()
            nmap_scan(ip_address_file, None)
            break
        if command == "2":
            ip_address = input_ip()
            nmap_scan(None, ip_address)
            break
        if command in exit_command:
            break                 #print("Back to main menu...")
        print(f"Invalid command: '{command}'.")


def main():
    """ Main function """
    def main_menu():
        print("**********Nmap Tool************************************")
        print("*  1 - Run Nmap with <IP> ping scan                   *")
        print("*  2 - Run Nmap with <IP> port and service scan       *")
        print("*  3 - Run Nmap with no guarantees                    *")
        print("*  7 - Read .txt file in current directory            *")
        print("*  8 - List existing .txt files in current directory  *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    while True:
        main_menu()
        main_input = input(">>> ")
        if main_input == "1":
            run_nmap("-T4 -sP")
        elif main_input == "2":
            run_nmap("-T4 -Pn -sV")
        elif main_input == "3":
            run_nmap_original()
        elif main_input == "7":
            read_file(select_file())
        elif main_input == "8":
            file_list()
        elif main_input in exit_command:
            print("Nmap tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")

if __name__ == "__main__":
    main()

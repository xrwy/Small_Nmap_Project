from flask import Flask, render_template, request
import nmap
import socket

numbers = [str(num) for num in range(0,11)]

scanner = nmap.PortScanner()

app = Flask(__name__)
 


@app.route('/', methods = ['GET'])
def scanner_():
    return render_template('scanner.html')
    
@app.route('/scanner_os', methods = ['GET'])
def scannerOs():
    return render_template('scanner_os.html')

@app.route('/scanner_regular', methods = ['GET'])
def scannerRegular():
    return render_template('scanner_regular.html')

@app.route('/scanner_ping', methods = ['GET'])
def scannerPing():
    return render_template('scanner_ping.html')



@app.route('/scanner_result', methods = ['GET','POST'])
def scannerResult():
    ipStatus = []
    protocols = []
    openPorts = []

    if request.method == 'POST':
        ipAddr = request.form['ip']
        option = request.form['type']
        portRange = request.form['port_range']

        if ipAddr == '' or option == '' or option == 'Type' or portRange == '':
            return 'Do Not Leave The Fields Blank / Fill in the Fields Properly.'
        
        range_ = portRange.split('-')
        len_ = ipAddr.split('.')
        if len(len_) == 4 and ipAddr[0].isalpha():
            ipAddr = socket.gethostbyname(ipAddr)
        else:
            if ipAddr[0] in numbers:
                pass
            else:
                try:
                    ipAddr = socket.gethostbyname(ipAddr)
                except:
                    return 'Please provide a valid url.'

        if len(portRange) == 1 or len(portRange) == 2:
            return 'Type the port range as specified. For Example : Start point-end point => 1-2000'
        elif '-' in portRange and len(portRange.split('-')) == 2:
            pass
        else:
            return 'Type the port range as specified. For Example : Start point-end point => 1-2000'

        if int(range_[0]) <= 0 or int(range_[1]) <= 0:
            return '<b>The starting or ending connection number cannot be 0 or less than 0.</b>'
        elif int(range_[1])>= 65535:
            return 'End connection number cannot be greater than 65535.'
        elif(int(range_[0]) >= int(range_[1])):
            return 'The start value point cannot be greater than the end value point. For Example : Start point-end point => 1-2000'



        if option == 'synack':
            # If user's input is 1, perform a SYN/ACK scan
            # Here, v is used for verbose, which means if selected it will give extra information
            # 1-1024 means the port number we want to search on
            #-sS means perform a TCP SYN connect scan, it send the SYN packets to the host
            try:
                scanner.scan(ipAddr, portRange, '-v -sS')
                # print(scanner.scaninfo())
                # state() tells if target is up or down
                # print("Ip Status: ", scanner[ip_addr].state())
                ipStatus.append(scanner[ipAddr].state())
                # all_protocols() tells which protocols are enabled like TCP UDP etc
                protocols = scanner[ipAddr].all_protocols()
                openPorts = list(scanner[ipAddr]['tcp'].keys())


                return render_template('scanner_result.html', ipStatus = ipStatus, protocols = protocols, openPorts = openPorts, scaninfo = scanner.scaninfo())
            
            except Exception as e:
                return '<b> Error : </b>' + str(e) 

        elif option == 'udp':
            # If user's input is 2, perform a UDP Scan   
            # Here, v is used for verbose, which means if selected it will give #extra information
            # 1-1024 means the port number we want to search on
            #-sU means perform a UDP SYN connect scan, it send the SYN packets to #the host
            try:
                scanner.scan(ipAddr, portRange, '-v -sU')
                # state() tells if target is up or down
                ipStatus.append(scanner[ipAddr].state())
                # all_protocols() tells which protocols are enabled like TCP UDP etc
                protocols = scanner[ipAddr].all_protocols()
                openPorts = list(scanner[ipAddr]['udp'].keys())

                return render_template('scanner_result.html', ipStatus = ipStatus, protocols = protocols, openPorts = openPorts, scaninfo = scanner.scaninfo())

            except Exception as e:
                return '<b> Error : </b>' + str(e) 


        elif option == 'comprehensive':
            # If user's input is 3, perform a Comprehensive scan
            # sS for SYN scan, sv probe open ports to determine what service and version they are running on
            # O determine OS type, A tells Nmap to make an effort in identifying the target OS
            
            try:
                scanner.scan(ipAddr, portRange, '-v -sS -sV -sC -A -O')
                ipStatus.append(scanner[ipAddr].state())
                protocols = scanner[ipAddr].all_protocols()
                openPorts = list(scanner[ipAddr]['tcp'].keys())     

                return render_template('scanner_result.html', ipStatus = ipStatus, protocols = protocols, openPorts = openPorts, scaninfo = scanner.scaninfo())

            except Exception as e:
                return '<b> Error : </b>' + str(e) 


        elif option == 'multiple':
            # Here, v is used for verbose, which means if selected it will give extra information
            # 1-1024 means the port number we want to search on
            #-sS means perform a TCP SYN connect scan, it send the SYN packets to the host
            
            try:
                scanner.scan(ipAddr,portRange, '-v -sS')
                # state() tells if target is up or down
                # all_protocols() tells which protocols are enabled like TCP UDP etc
                ipStatus.append(scanner[ipAddr].state())
                protocols = scanner[ipAddr].all_protocols()
                openPorts = list(scanner[ipAddr]['tcp'].keys()) 

                return render_template('scanner_result.html', ipStatus = ipStatus, protocols = protocols, openPorts = openPorts, scaninfo = scanner.scaninfo())

            except Exception as e:
                return '<b> Error : </b>' + str(e) 

    else:
        return 'For post requests only.'


@app.route('/scanner_os_result', methods = ['GET','POST'])
def scannerOsResult():
    if request.method == 'POST':
        ip = request.form['ip']
        if ip == '':
            return 'Do Not Leave The Fields Blank'
        
        len_ = ip.split('.')
        if len(len_) == 4 and ip[0].isalpha():
            ip = socket.gethostbyname(ip)
        else:
            if ip[0] in numbers:
                pass
            else:
                try:
                    ip = socket.gethostbyname(ip)
                except:
                    return 'Please provide a valid url.'  
        try:
            res = scanner.scan(ip, arguments="-O")['scan'][ip]['osmatch'][1]
            return render_template('scanner_result_os.html', result_ = str(res))
        except Exception as e:
            return '<b>Error !!! : </b>' + str(e)

    else:
        return 'For post requests only.'

@app.route('/scanner_regular_result', methods = ['GET','POST'])
def scannerRegularResult():
    ipStatus = []
    if request.method == 'POST':
        ip = request.form['ip']
        # If user's input is 4, perform a Regular Scan
        # Works on default arguments

        if ip == '':
            return 'Do Not Leave The Fields Blank'

        len_ = ip.split('.')
        if len(len_) == 4 and ip[0].isalpha():
            ip = socket.gethostbyname(ip)
        else:
            if ip[0] in numbers:
                pass
            else:
                try:
                    ip = socket.gethostbyname(ip)
                except:
                    return 'Please provide a valid url.'

        scanner.scan(ip)
        ipStatus.append(scanner[ip].state())
        protocols = scanner[ip].all_protocols()
        openPorts = list(scanner[ip]['tcp'].keys())     

        return render_template('scanner_result.html', ipStatus = ipStatus, protocols = protocols, openPorts = openPorts, scaninfo = scanner.scaninfo())

    else:
        return 'For post requests only.'


@app.route('/scanner_ping_result', methods = ['GET','POST'])
def scannerPingResult():
    if request.method == 'POST':
        ip = request.form['ip']
        episode = request.form['episode']

        if ip == '' or episode == '' or episode == 'episode':
            return '<b>Do Not Leave The Fields Blank / Fill in the Fields Properly!!!</b>'

        len_ = ip.split('.')
        if len(len_) == 4 and ip[0].isalpha():
            ip = socket.gethostbyname(ip)
        else:
            if ip[0] in numbers:
                pass
            else:
                try:
                    ip = socket.gethostbyname(ip)
                except:
                    return 'Please provide a valid url.'

        res = []
        hosts_ = '{0}/{1}'.format(str(ip), str(episode))
        scanner.scan(hosts=hosts_, arguments='-n -sP -PE -PA21,23,80,3389')
        hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host, status in hosts_list:
            res.append('{0}:{1}'.format(host, status))
        return render_template('scanner_result_ping.html', res_ = res)

    else:
        return 'For post requests only.'
        

if __name__ == '__main__':
	app.run(debug=True)


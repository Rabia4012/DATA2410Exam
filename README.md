# DATA2410Exam
To run this code, you need to open two terminals.
In mininet you can open h1 and h2, from the topology. 

You will run the server on h2, and the client on h1.

To run the server on h2:
python3 application.py -s -i <ip-address> -p <port number>

For example:
python3 application.py -s -i 10.0.1.2 -p 8080

To run the server, and discard a packet:
python3 application.py -s -i <ip-address> -p <port number> -d <packet to discard>

To run the client on h1, with defeault window size 3:
pyhton3 application.py -c -f <Image-name.jpg> -i <ip-address> -p <port number>

For example:
python3 application.py -c -f Photo.jpg -i 10.0.1.2 -p 8080

To run client on h1, with selected window size:
pyhton3 application.py -c -f <Image-name.jpg> -i <ip-address> -p <port number> -w <window size>

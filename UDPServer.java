import java.io.*;
import java.net.*;

class UDPServer
{
   public static void main(String args[]) throws Exception
      {
	   System.out.println("Inicia Servidor...");
         DatagramSocket serverSocket = new DatagramSocket(9876);
            byte[] receiveData = new byte[1024];
            byte[] sendData;
            while(true)
               {
                //Recibe paquete
                  DatagramPacket receivePacket = new DatagramPacket(receiveData,
                        receiveData.length);
                  serverSocket.receive(receivePacket);
                  
                  //Pasa a String
                  String sentence = new String( receivePacket.getData(),
			receivePacket.getOffset(),receivePacket.getLength());
                  System.out.println("RECEIVED: " + sentence + "-"+sentence.length());
                  
                  //Se devuelve
                  /*InetAddress IPAddress = receivePacket.getAddress();
                  int port = receivePacket.getPort();
                  String capitalizedSentence = sentence.toUpperCase();
                  sendData = capitalizedSentence.getBytes();
                  DatagramPacket sendPacket =
                  new DatagramPacket(sendData, sentence.intern().length(), IPAddress, port);
                  serverSocket.send(sendPacket);
                  receiveData = new byte[1024];*/
               }
      }
}

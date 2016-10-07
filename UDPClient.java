import java.io.*;
import java.net.*;

class UDPClient
{
   public static void main(String args[]) throws Exception
   {
	   System.out.println("Inicia Cliente...");
      //Inicializa variables
      BufferedReader inFromUser =
         new BufferedReader(new InputStreamReader(System.in));
      byte[] sendData = new byte[1024];
      byte[] receiveData = new byte[1024];
      
      //Leemos IP Destino
      System.out.print("Introduzca IP Destino: ");
      String ip = inFromUser.readLine();
      System.out.print("Introduzca Puerto Origen: ");
      int srcport = Integer.parseInt(inFromUser.readLine());
      DatagramSocket clientSocket = new DatagramSocket(srcport);
      InetAddress IPAddress = InetAddress.getByName(ip);
      
      //Se lee y envia paquete
      System.out.print("Contenido: ");
      String sentence = inFromUser.readLine();
      sendData = sentence.getBytes();
      DatagramPacket sendPacket = new DatagramPacket(sendData,
        sendData.length, IPAddress, 9876);
      clientSocket.send(sendPacket);
      
      //Se recibe paquete
      DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
      clientSocket.receive(receivePacket);
      String modifiedSentence = new String(receivePacket.getData());
      System.out.println("FROM SERVER:" + modifiedSentence);
      clientSocket.close();
   }
}

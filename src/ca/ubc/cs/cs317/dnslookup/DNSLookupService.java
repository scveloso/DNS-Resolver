package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.io.*;
import java.net.*;
import java.util.*;
import java.nio.ByteBuffer;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

          try {
          String domain = node.getHostName();
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          DataOutputStream dos = new DataOutputStream(baos);

          // Identifier
          short identifier = 0x1234;
          dos.writeShort(0x1234);

          System.out.println("Query ID     " + identifier + " " + domain + " A --> " + rootServer);

          // 1 bit flag indicating query and no error
          dos.writeShort(0x0000);

          // Query count: number of questions in the question section of the message
          dos.writeShort(0x0001);

          // Answer count: number of resource records in the Answer section of the message
          dos.writeShort(0x0000);

          // Name server records: number of recourse records in the Authority section of the message
          dos.writeShort(0x0000);

          // Additional record count: specifies number of recourse records in additional section of the message
          dos.writeShort(0x0000);

          String[] domainParts = domain.split("\\.");
          for (int i = 0; i < domainParts.length; i++) {
              byte[] domainBytes = domainParts[i].getBytes("UTF-8");
              dos.writeByte(domainBytes.length);  // length of a label
              dos.write(domainBytes);             // the actual label
          }

          // End of the QNAME
          dos.writeByte(0x00);

          // QTYPE - Type 0x01 = A host request)
          dos.writeShort(0x0001);

          // QCLASS - Class 0x01 = IN
          dos.writeShort(0x0001);

          byte[] dnsFrame = baos.toByteArray();

          // System.out.println("Sending datagram:");
          // for (int i = 0; i < dnsFrame.length; i++) {
          //     System.out.print("0x" + String.format("%x", dnsFrame[i]) + " ");
          // }

          //System.out.println("");

          // Send DNS Request Frame
          DatagramSocket socket = new DatagramSocket();
          DatagramPacket dnsReqPacket = new DatagramPacket(dnsFrame, dnsFrame.length, rootServer, 53);
          socket.send(dnsReqPacket);

          // Await response from DNS server
          byte[] buf = new byte[1024];
          DatagramPacket dnsResponsePacket = new DatagramPacket(buf, buf.length);
          socket.receive(dnsResponsePacket);

          // System.out.println("Receiving datagram:");
          // for (int i = 0; i < dnsResponsePacket.getLength(); i++) {
          //     System.out.print(" 0x" + String.format("%x", buf[i]) + " ");
          // }
          // System.out.println("\n");

          // Beginning of extracting information from response
          int offset = 0;
          short ID = (short)((buf[offset] << 8) + (buf[offset + 1]));
          offset += 2;
          short flags = (short)((buf[offset] <<8) + (buf[offset + 1]));
          boolean authoritative;
          if ((flags & 0x04) == 0x04) { // check if authoritative
            authoritative = true;
          } else {
            authoritative = false;
          }
          offset += 2;
          System.out.println("Response ID: " + ID + " Authoritative = " + authoritative);
          short questions = (short)((buf[offset] <<8) + (buf[offset + 1]));
          offset += 2;
          short answerRRs = (short)((buf[offset] <<8) + (buf[offset + 1]));
          offset +=2;
          System.out.println("Answers (" + (int) answerRRs + ")");
          short authorityRRs = (short)((buf[offset] <<8) + (buf[offset + 1]));
          offset +=2;
          System.out.println("Nameservers (" + (int) authorityRRs + ")");
          short additionalRRs = (short)((buf[offset] <<8) + (buf[offset + 1]));
          offset +=2;

          // Extracting Questions
          for (int j = 0; j < (int) questions; j++) {
            String qName = getNameFromBuffer(buf, offset);
            qName = qName.substring(0, qName.length() - 1);
            System.out.println("qName: " + qName);

            String[] nameArr = qName.split("\\.");
            for (int i = 0; i < nameArr.length; i++) {
              offset +=1;
              for (char nameChar : nameArr[i].toCharArray()) {
                offset += 1;
              }
            }
            offset += 1;

            StringBuilder qType = new StringBuilder();
            qType.append("0x");
            qType.append(String.format("%02x", buf[offset]));
            qType.append(String.format("%02x", buf[offset + 1]));
   	        System.out.println("qType: " + qType.toString());
            offset += 2;
            StringBuilder qClass = new StringBuilder();
            qClass.append("0x");
            qClass.append(String.format("%02x", buf[offset]));
            qClass.append(String.format("%02x", buf[offset + 1]));
   	        System.out.println("qClass: " + qClass.toString());
            offset += 2;
          }

          // Extracting Nameservers
          // TODO: find out if pointers only happen in domain names or names
          // TODO: Finish extracting nameservers
          for (int k = 0; k < (int) authorityRRs; k++) {
            // Get the nsName
            short nsName = (short)((buf[offset] <<8) + (buf[offset + 1]));
            offset +=2;

            if ((nsName & 0xc000) == 0xc000) { // pointer found
              short ptrOffset = (short)(nsName & 0x3FFF);

              // given buffer, and offset, get the string at that offset
              String strNsName = "";
              byte addrLen = buf[ptrOffset];
              for (int i = 1; i <= addrLen; i++) {
                strNsName += (char) (buf[ptrOffset + i] & 0xFF);
              }

              System.out.println("nsName: " + strNsName);
            }

            // Get the nsType
            short nsType = (short)((buf[offset] <<8) + (buf[offset + 1]));
            System.out.println("nsType: "+ String.format("0x%04X", nsType));
            offset += 2;

            // Get the nsClass
            short nsClass = (short)((buf[offset] <<8) + (buf[offset + 1]));
            System.out.println("nsClass: "+ String.format("0x%04X", nsClass));
            offset += 2;

            // Get the ttl
            byte[] bufTTL = new byte[4];
            bufTTL[0] = buf[offset];
            bufTTL[1] = buf[offset + 1];
            bufTTL[2] = buf[offset + 2];
            bufTTL[3] = buf[offset + 3];
            int nsTTL = ByteBuffer.wrap(bufTTL).getInt();
            System.out.println("nsTTL: "+ nsTTL);
            offset += 4;

            // Get the nsDataLen
            short nsDataLen = (short)((buf[offset] <<8) + (buf[offset + 1]));
            System.out.println("nsDataLen: "+ String.format("0x%04X", nsDataLen));
            offset += 2;

            // Get ns
            String nameServer = getNameFromBuffer(buf, offset);
            nameServer = nameServer.substring(0, nameServer.length() - 1);
            System.out.println("Name Server: " + nameServer);

            // Update offset according to name
            String[] nameArr = nameServer.split("\\.");
            for (int i = 0; i < nameArr.length; i++) {
              offset +=1;
              for (char nameChar : nameArr[i].toCharArray()) {
                offset += 1;
              }
            }
            offset -=1;
          }

          DataInputStream din = new DataInputStream(new ByteArrayInputStream(buf));
          System.out.println("Transaction ID: 0x" + String.format("%x", din.readShort()));
          System.out.println("Flags: 0x" + String.format("%x", din.readShort()));
          System.out.println("Questions: 0x" + String.format("%x", din.readShort()));
          System.out.println("Answers RRs: 0x" + String.format("%x", din.readShort()));
          System.out.println("Authority RRs: 0x" + String.format("%x", din.readShort()));
          System.out.println("Additional RRs: 0x" + String.format("%x", din.readShort()));

          int recLen = 0; // record length
          while ((recLen = din.readByte()) > 0) {
              byte[] record = new byte[recLen];

              for (int i = 0; i < recLen; i++) {
                  record[i] = din.readByte();
              }

              System.out.println("Record: " + new String(record, "UTF-8"));
          }

          System.out.println("Record Type: 0x" + String.format("%x", din.readShort()));
          System.out.println("Class: 0x" + String.format("%x", din.readShort()));

          System.out.println("Authoritative Name Servers");


          // First data
          System.out.println("Name: " + String.format("%x", din.readShort()));
          System.out.println("Type: " + String.format("%x", din.readShort()));
          System.out.println("Class: " + String.format("%x", din.readShort()));
          System.out.println("TTL: " + String.format("%x, %x", din.readShort(), din.readShort()));
          short dataLen = din.readShort();
          System.out.println("Data len: 0x" + String.format("%x", dataLen));

          String name = getNameFromBuffer(buf, 39);
          name = name.substring(0, name.length() - 1);

          // int len = din.readByte(); // read len of 01
          // for (int i = 0; i < len; i++) {
          //   System.out.print((char) (din.readByte() & 0xFF));
          // }
          // System.out.print(".");
          //
          // len = din.readByte(); // read len of 01
          // for (int i = 0; i < len; i++) {
          //   System.out.print((char) (din.readByte() & 0xFF));
          // }
          // System.out.print(".");
          // System.out.println("");
          //
          // short ptrLen = din.readShort();
          // if ((ptrLen & 0xc000) == 0xc000) {
          //   System.out.println("Pointer found");
          //   short offset = (short)(ptrLen & 0x3FFF);
          //   int intOffset = offset;
          //   System.out.println("intoffset: " + intOffset);
          //
          //   // given buffer, and offset, get the string at that offset
          //   String addr = "";
          //   byte addrLen = buf[offset];
          //   for (int i = 1; i <= addrLen; i++) {
          //     addr += (char) (buf[offset + i] & 0xFF);
          //   }
          //
          //   System.out.println("addr: " + addr);
          //
          //   System.out.println("offset: " + String.format("%x", offset));
          // }
          System.out.println("");

        } catch (Exception e) {
          System.out.println("Exception: " + e);
        }

        // TODO To be completed by the student


        return cache.getCachedResults(node);
    }

    private static String getNameFromBuffer(byte[] buf, int offset) {
      String name = "";
      int len = buf[offset];

      if (len == 0) {
        return name;
      }

      if ((len & 0xc0) == 0xc0) { // if it is a pointer
        short s = (short)((len << 8) + buf[offset + 1]);
        short ptrOffset = (short) (s & 0x3FFF);

        name += getNameFromBuffer(buf, ptrOffset);
      } else { // if not a pointer
        for (int i = 1; i <= len; i++) {
          name += (char) (buf[offset + i] & 0xFF);
        }
        name += ".";
        name += getNameFromBuffer(buf, offset + len + 1);
      }

      return name;
    }

    private static String getNameFromPointerInBuffer(byte[] buf, int ptrOffset) {
      String name = "";
      int len = buf[ptrOffset];

      if (len == 0) {
        return name;
      }

      for (int i = 1; i <= len; i++) {
        name += (char) (buf[ptrOffset + i] & 0xFF);
      }
      name += ".";
      name += getNameFromPointerInBuffer(buf, ptrOffset + len + 1);

      return name;
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {

        // TODO To be completed by the student
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}

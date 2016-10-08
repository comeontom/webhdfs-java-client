import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.*;
import sun.misc.BASE64Encoder;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.*;

/**
 * <p>Client logs in to a Key Distribution Center (KDC) using JAAS and then
 * requests a service ticket for the server, base 64 encodes it and writes it
 * to the file <i>service-ticket.txt</i>.</p>
 * <p>This class, in combination with the <i>Server</i> class illustrates the 
 * use of the JAAS and GSS APIs for initiating a security context using the
 * Kerberos protocol.</p>
 * <p>This requires a KDC/domain controller such as Active Directory or Apache
 * Directory. The KDC configuration details are stored in the 
 * <i>client.properties</i> file, while the JAAS details are stored in the
 * file <i>jaas.conf</i>.</p>
 * @author Ants
 */
public class Client {

  static Properties props = new Properties();

  /**
   * Kerberos context configuration for the JDK GSS library.
   */
  private static class KerberosConfiguration extends Configuration {
    private String keytab;
    private String principal;


    public KerberosConfiguration(String keytab, String principal) {
      this.keytab = keytab;
      this.principal = principal;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
      Map<String, String> options = new HashMap<String, String>();
      boolean IBM_JAVA = false;

      if (IBM_JAVA) {
        options.put("useKeytab",
                keytab.startsWith("file://") ? keytab : "file://" + keytab);
        options.put("principal", principal);
        options.put("credsType", "acceptor");
      } else {
        options.put("keyTab", keytab);
        options.put("principal", principal);
        options.put("useKeyTab", "true");
        options.put("storeKey", "true");
        options.put("doNotPrompt", "true");
        options.put("useTicketCache", "true");
        options.put("renewTGT", "true");
        options.put("isInitiator", "false");
      }
      options.put("refreshKrb5Config", "true");
      String ticketCache = System.getenv("KRB5CCNAME");
      if (ticketCache != null) {
        if (IBM_JAVA) {
          options.put("useDefaultCcache", "true");
          // The first value searched when "useDefaultCcache" is used.
          System.setProperty("KRB5CCNAME", ticketCache);
          options.put("renewTGT", "true");
          options.put("credsType", "both");
        } else {
          options.put("ticketCache", ticketCache);
        }
      }
      options.put("debug", "true");

      return new AppConfigurationEntry[] {
              new AppConfigurationEntry(KerberosUtil.getKrb5LoginModuleName(),
                      AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                      options), };
    }
  }
  
  public static void main( String[] args) {
    try {
      System.setProperty("java.security.krb5.conf", "/Users/comeontom/Desktop/kerberos/krb5.conf");
      System.setProperty("javax.security.auth.useSubjectCredsOnly","true"); // 不需要互动,输入密码

      // Setup up the Kerberos properties.
      props.load(new FileInputStream("/Users/comeontom/Desktop/kerberos/webhdfs-java-client/src/main/resources/client.properties"));
      System.setProperty( "sun.security.krb5.debug", "true");
      System.setProperty( "java.security.krb5.realm", props.getProperty("realm")); //"BCSOFT.LOCAL"); //"EXAMPLE.COM");
      System.setProperty( "java.security.krb5.kdc", props.getProperty("kdc")); //"havana"); //localhost");
      System.setProperty( "java.security.auth.login.config", "/Users/comeontom/Desktop/kerberos/webhdfs-java-client/src/main/resources/jaas.conf");

      String username = props.getProperty( "client.principal.name");
      String password = props.getProperty( "client.password");

      // Oid mechanism = use Kerberos V5 as the security mechanism.
      krb5Oid = new Oid( "1.2.840.113554.1.2.2");
      Client client = new Client();
      // Login to the KDC.
      client.login( username, password);

      // Request the service ticket.
      client.initiateSecurityContext(props.getProperty("service.principal.name"));
      // Write the ticket to disk for the server to read.
      encodeAndWriteTicketToDisk(client.serviceTicket, "/Users/comeontom/Desktop/kerberos/webhdfs-java-client/src/main/resources/security.token");

      System.out.println( "Service ticket encoded to disk successfully");
    } catch ( LoginException e) {
      e.printStackTrace();
      System.err.println( "There was an error during the JAAS login");
      System.exit( -1);
    } catch ( GSSException e) {
      e.printStackTrace();
      System.err.println( "There was an error during the security context initiation");
      System.exit( -1);
    } catch ( IOException e) {
      e.printStackTrace();
      System.err.println( "There was an IO error");
      System.exit( -1);
    }
  }
  
  public Client() {
    super();
  }
  
  private static Oid krb5Oid;
  
  private Subject subject;
  private byte[] serviceTicket;
  
  // Authenticate against the KDC using JAAS.
  private void login( String username, String password) throws LoginException {
    LoginContext loginCtx = null;
    String principal = props.getProperty("principal");
    String keytab = props.getProperty("keytab");

    // "Client" references the JAAS configuration in the jaas.conf file.
    Set<Principal> principals = new HashSet<Principal>();
    principals.add(new KerberosPrincipal(principal));
    Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());
    KerberosConfiguration kerberosConfiguration = new KerberosConfiguration(keytab, principal);

    // "Client" references the JAAS configuration in the jaas.conf file.
    loginCtx = new LoginContext("", subject, null, kerberosConfiguration);
    // loginCtx = new LoginContext( "Client", new LoginCallbackHandler( username, password));

    loginCtx.login();
    this.subject = loginCtx.getSubject();
  }
  
  // Begin the initiation of a security context with the target service.
  private void initiateSecurityContext(String servicePrincipalName) throws GSSException {
    GSSManager manager = GSSManager.getInstance();
    GSSName serverName = manager.createName(servicePrincipalName, GSSName.NT_HOSTBASED_SERVICE);
    final GSSContext context = manager.createContext( serverName, krb5Oid, null, GSSContext.DEFAULT_LIFETIME);
    // The GSS context initiation has to be performed as a privileged action.
    this.serviceTicket = Subject.doAs( subject, new PrivilegedAction<byte[]>() {
      public byte[] run() {

        try {
          byte[] token = new byte[0];
          // This is a one pass context initialisation.
          context.requestMutualAuth( false);
          context.requestCredDeleg( false);
          return context.initSecContext( token, 0, token.length);
        }
        catch ( GSSException e) {
          e.printStackTrace();
          return null;
        }
      }
    });
    
  }

  // Base64 encode the raw ticket and write it to the given file.
  private static void encodeAndWriteTicketToDisk( byte[] ticket, String filepath) 
      throws IOException {
    BASE64Encoder encoder = new BASE64Encoder();            
    FileWriter writer = new FileWriter( new File( filepath));
    String encodedToken = encoder.encode( ticket);
    writer.write( encodedToken);
    writer.close();
  }
}

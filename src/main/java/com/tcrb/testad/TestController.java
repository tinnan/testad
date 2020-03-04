package com.tcrb.testad;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.time.Duration;
import java.time.Instant;
import java.util.Hashtable;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    private static String[] userAttributes = {
            "distinguishedName","cn","name","uid",
            "sn","givenname","memberOf","samaccountname",
            "userPrincipalName"
    };

    @Value("${ldap.domain}")
    private String domainName;
    @Value("${ldap.server}")
    private String serverName;
    @Value("${ldap.username}")
    private String username;
    @Value("${ldap.password}")
    private String password;

    @GetMapping("/ad/hello")
    public String hello() {

        return "Test AD server is up.";
    }

    @GetMapping("/ad/test")
    public TestResponse adTest(@RequestParam("username") String getuser) throws Exception {

        Instant start = Instant.now();
        LdapContext context = connect(domainName, serverName, username, password);
        Instant connectFinish = Instant.now();
        User user = getUser(context, getuser);
        Instant searchUserFinish = Instant.now();

        Duration startToFinishConnect = Duration.between(start, connectFinish);
        Duration connectToFinishSearch = Duration.between(connectFinish, searchUserFinish);

        return new TestResponse(user,
                startToFinishConnect.toMillis() + " ms",
                connectToFinishSearch.toMillis() + "ms");
    }

    public static class TestResponse {
        private User user;
        private String elapsedStartToFinishConnect;
        private String elapsedConnectToFinishSearchUser;

        public TestResponse(User user, String elapsedStartToFinishConnect, String elapsedConnectToFinishSearchUser) {
            this.user = user;
            this.elapsedStartToFinishConnect = elapsedStartToFinishConnect;
            this.elapsedConnectToFinishSearchUser = elapsedConnectToFinishSearchUser;
        }

        public User getUser() {
            return user;
        }

        public void setUser(User user) {
            this.user = user;
        }

        public String getElapsedStartToFinishConnect() {
            return elapsedStartToFinishConnect;
        }

        public void setElapsedStartToFinishConnect(String elapsedStartToFinishConnect) {
            this.elapsedStartToFinishConnect = elapsedStartToFinishConnect;
        }

        public String getElapsedConnectToFinishSearchUser() {
            return elapsedConnectToFinishSearchUser;
        }

        public void setElapsedConnectToFinishSearchUser(String elapsedConnectToFinishSearchUser) {
            this.elapsedConnectToFinishSearchUser = elapsedConnectToFinishSearchUser;
        }
    }

    private LdapContext connect(String domainName, String serverName, String username, String password) throws Exception {
        if (domainName==null){
            try{
                String fqdn = java.net.InetAddress.getLocalHost().getCanonicalHostName();
                if (fqdn.split("\\.").length>1) domainName = fqdn.substring(fqdn.indexOf(".")+1);
            }
            catch(java.net.UnknownHostException e){}
        }

        //System.out.println("Authenticating " + username + "@" + domainName + " through " + serverName);

        if (password!=null){
            password = password.trim();
            if (password.length()==0) password = null;
        }

        //bind by using the specified username/password
        Hashtable<String, String> props = new Hashtable<>();
        String principalName = username;
        if (StringUtils.hasText(domainName)) {
            principalName += "@" + domainName;
        }
        logger.info("User to authenticate: " + principalName);
        props.put(Context.SECURITY_PRINCIPAL, principalName);
        if (password!=null) props.put(Context.SECURITY_CREDENTIALS, password);

        // Build LDAP URL.
        String ldapURL = "ldap://";
        if (StringUtils.hasText(serverName)) {
            ldapURL += serverName;
        }
        if (StringUtils.hasText(serverName) && StringUtils.hasText(domainName)) {
            ldapURL += ".";
        }
        if (StringUtils.hasText(domainName)) {
            ldapURL += domainName;
        }
        ldapURL += "/";
        logger.info("LDAP URL: " + ldapURL);
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapURL);
        try{
            return new InitialLdapContext(props, null);
        }
        catch(javax.naming.CommunicationException e){
//            throw new NamingException("Failed to connect to " + domainName + ((serverName==null)? "" : " through " + serverName));
            throw e;
        }
        catch(NamingException e){
            throw new NamingException("Failed to authenticate " + principalName + ((serverName==null)? "" : " through " + serverName));
        }
    }

    private User getUser(LdapContext context, String username) throws Exception {
        try{
            String domainName = null;
            if (username.contains("@")){
                username = username.substring(0, username.indexOf("@"));
                domainName = username.substring(username.indexOf("@")+1);
            }
            else if(username.contains("\\")){
                username = username.substring(0, username.indexOf("\\"));
                domainName = username.substring(username.indexOf("\\")+1);
            }
            else{
                String authenticatedUser = (String) context.getEnvironment().get(Context.SECURITY_PRINCIPAL);
                if (authenticatedUser.contains("@")){
                    domainName = authenticatedUser.substring(authenticatedUser.indexOf("@")+1);
                }
            }

            String principalName = username;
            if (StringUtils.hasText(domainName)) {
                principalName += "@" + domainName;
            }
            logger.info("Retrieving user: " + principalName);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(userAttributes);
            NamingEnumeration<SearchResult> answer = context.search( toDC(domainName), "(& (userPrincipalName="+principalName+")(objectClass=user))", controls);
            if (answer.hasMore()) {
                Attributes attr = answer.next().getAttributes();
                Attribute user = attr.get("userPrincipalName");
                if (user!=null) return new User(attr);
            }

        }
        catch(NamingException e){
            throw e;
        }

        return null;
    }

    private String toDC(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if(token.length()==0)   continue;   // defensive check
            if(buf.length()>0)  buf.append(",");
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }

    public static class User {
        private String distinguishedName;
        private String userPrincipal;
        private String commonName;

        public User(Attributes attr) throws javax.naming.NamingException {
            userPrincipal = (String) attr.get("userPrincipalName").get();
            commonName = (String) attr.get("cn").get();
            distinguishedName = (String) attr.get("distinguishedName").get();
        }

        public String getUserPrincipal(){
            return userPrincipal;
        }

        public String getCommonName(){
            return commonName;
        }

        public String getDistinguishedName(){
            return distinguishedName;
        }

        public String toString(){
            return getDistinguishedName();
        }
    }
}

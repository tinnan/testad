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
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.Hashtable;

@RestController
public class TestController {

    private static final Logger logger = LoggerFactory.getLogger(TestController.class);

    private static String[] ldapAttributes = {
            "distinguishedName","cn","name","uid",
            "sn","givenname","memberOf","samaccountname",
            "userPrincipalName", "objectClass", "objectCategory",
            "displayName",
    };

    @Value("${ldap.url}")
    private String ldapUrl;
    @Value("${ldap.username}")
    private String username;
    @Value("${ldap.password}")
    private String password;
    @Value("${ldap.search.filter}")
    private String searchFilter;

    @GetMapping("/ad/hello")
    public String hello() {

        return "Test AD server is up.";
    }

    @GetMapping("/ad/test")
    public TestResponse adTest(
            @RequestParam("searchDc") String searchDc,
            @RequestParam("searchParam") String searchParam) throws Exception {

        Instant start = Instant.now();
        logger.info("Connect starts at: " + start.toString());
        LdapContext context = connect(ldapUrl, username, password);
        Instant connectFinish = Instant.now();
        logger.info("Get user starts at: " + connectFinish.toString());
        User user = getUser(context, searchDc, searchFilter, searchParam);
        Instant searchUserFinish = Instant.now();
        logger.info("Get user finishes at: " + searchUserFinish.toString());

        return new TestResponse(user,
                start,
                connectFinish,
                searchUserFinish);
    }

    public static class TestResponse {
        private User result;
        private Instant start;
        private Instant connectFinish;
        private Instant searchUserFinish;
        private String durationToConnectFinish;
        private String durationToSearchUserFinish;

        public TestResponse(User result, Instant start, Instant connectFinish, Instant searchUserFinish) {
            this.result = result;
            this.start = start;
            this.connectFinish = connectFinish;
            this.searchUserFinish = searchUserFinish;
            this.durationToConnectFinish = Duration.between(start, connectFinish).toMillis() + " ms.";
            this.durationToSearchUserFinish = Duration.between(connectFinish, searchUserFinish).toMillis() + " ms.";
        }

        public User getResult() {
            return result;
        }

        public void setResult(User result) {
            this.result = result;
        }


        public Instant getStart() {
            return start;
        }

        public void setStart(Instant start) {
            this.start = start;
        }

        public Instant getConnectFinish() {
            return connectFinish;
        }

        public void setConnectFinish(Instant connectFinish) {
            this.connectFinish = connectFinish;
        }

        public Instant getSearchUserFinish() {
            return searchUserFinish;
        }

        public void setSearchUserFinish(Instant searchUserFinish) {
            this.searchUserFinish = searchUserFinish;
        }

        public String getDurationToConnectFinish() {
            return durationToConnectFinish;
        }

        public void setDurationToConnectFinish(String durationToConnectFinish) {
            this.durationToConnectFinish = durationToConnectFinish;
        }

        public String getDurationToSearchUserFinish() {
            return durationToSearchUserFinish;
        }

        public void setDurationToSearchUserFinish(String durationToSearchUserFinish) {
            this.durationToSearchUserFinish = durationToSearchUserFinish;
        }
    }

    private LdapContext connect(String ldapUrl, String username, String password) throws Exception {

        //bind by using the specified username/password
        Hashtable<String, Object> props = new Hashtable<>();
        logger.info("User to authenticate: " + username);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        if (StringUtils.hasText(username)) {
            props.put(Context.SECURITY_PRINCIPAL, username);
        }
        if (StringUtils.hasText(password)) {
            props.put(Context.SECURITY_CREDENTIALS, password);
        }

        // Build LDAP URL.
        logger.info("LDAP URL: " + ldapUrl);
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapUrl);
        try{
            return new InitialLdapContext(props, null);
        }
        catch(javax.naming.CommunicationException e){
            throw e;
        }
        catch(NamingException e){
            throw e;
        }
    }

    private User getUser(LdapContext context, String searchDc, String searchFilter, String searchParam) throws Exception {
        try{

            String[] searchParams = searchParam.split(",");
            logger.info("Search filter before formatting: " + searchFilter);
            logger.info("Search params: " + searchParams);
            searchDc = toDC(searchDc);
            searchFilter = MessageFormat.format(searchFilter, searchParams);
            logger.info("Search base: " + searchDc);
            logger.info("Search filter: " + searchFilter);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(ldapAttributes);
            NamingEnumeration<SearchResult> answer = context.search(searchDc, searchFilter, controls);
            logger.info("Search finished.");
            int count = 1;
            if (answer.hasMore()) {
                Attributes attr = answer.next().getAttributes();
                Attribute user = attr.get("userPrincipalName");
                logger.info("============== Search result [" + (count++) +"] ==============");
                infoLogSearchResult(attr);
                return new User(attr);
            }

        }
        catch(NamingException e){
            throw e;
        }

        return null;
    }

    private void infoLogSearchResult(Attributes attrs) throws Exception {
        for (String attrName : ldapAttributes) {
            Attribute attr = attrs.get(attrName);
            Object message = attr == null ? "" : attr.get();
            logger.info("Result [" + attrName + "] : " + message);
        }
    }

    private String toDC(String domainName) {
        if (!StringUtils.hasText(domainName))
            return "";
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
            if (attr.get("userPrincipalName") != null) userPrincipal = (String) attr.get("userPrincipalName").get();
            if (attr.get("cn") != null) commonName = (String) attr.get("cn").get();
            if (attr.get("distinguishedName") != null) distinguishedName = (String) attr.get("distinguishedName").get();
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

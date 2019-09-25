---
layout: post
title:  "Securing your web application with Spring Boot and Kotlin."
date:   2018-4-17 10:35:57 -0500
categories: 
---
#Securing your web application with Spring Boot and Kotlin.

So you’re building the next Uber for Cats - the internet is going to love it. But before you get your millions of users, the venture capital, and your boatload of cash, you need to handle a few things - like user login and how users can be sure their data is safe. Only a user and third-party applications granted access by your users should be able to access their private data. You might think about it a bit and decide to write your own custom security framework - but should you?

User authentication and authorization is a hard problem to solve from scratch and can be tricky. We can attempt implementing a custom authorization protocol, but by reinventing the wheel, we risk vulnerabilities unknown to us - security in the general case should be left to the experts: unless you really know what you're doing, chances are your code will have security flaws.

Furthermore, in a world of multiple web services, users often expect the ability to share their data across multiple applications: using a standard protocol supported across the web ecosystems means integrating with your system is easy and predictable - ideally as easy as plugging your application's specific configuration values to a library like [Scribe](https://github.com/scribejava/scribejava) or [AppAuth](https://appauth.io/).

##O what?
OAuth is an authorization open standard allowing users to sign into multiple services with well defined resource access scopes without sharing passwords. OAuth works through delegation to a trusted authorization provider. It allows users to grant third parties (like other users or web applications) access to their information without the sharing of passwords, separating the concept of a user, and user access, by delegating to an authorization server. Since there's no need to share passwords with external agents and with authorization decoupled from passwords, users can change their passwords without breaking user sign-in sessions. With widespread use across the industry including Google, Facebook, Microsoft, Amazon, and Vena - there are many libraries across multiple languages for handling OAuth authorization.

There are four basic roles in OAuth V2, the latest version of OAuth, and the version we’ll be building our authorization server with:

**Resource Owner** - this is the user with ownership of a resource. A resource is any unit of information meaningful in a secure context. This could be a picture, user profile, or bank account details - it can basically be thought of as anything that is accessed by the URL you supply (in a RESTful context).

**Resource Server** - the web service hosting the user’s protected resources.

**Client** - this is any application accessing a user resource on behalf of that user. This separation allows multiple applications to use the same authorization server to access a user resource. This also means that your application can grant access to third-party services, allowing them to access and change user data on behalf of your users.

**Authorization Server** - this service is responsible for proving users have granted some scoped access of their resources to client applications. The authorization server issues short-lived "access tokens" as proof of grant - resource servers can check this token with the authorization server, using the result to control client access to user resources. Optionally, another long lived refresh token can be issued: a client can repeatedly trade this for new access tokens.

Now with all that information out of the way, let’s get started on our server!

We’ll use the Spring Boot web framework built on top Spring for our authorization server. Its convention over configuration philosophy and excellent support for the OAuth V2 protocol means you can pretty much have your own authorization server up and running by the end of this blog post. Our sample server will be written in Kotlin using Gradle as the build system. Spring is written primarily in Java but has excellent support for Kotlin. In fact, the latest iteration of Spring, Spring 5, supports Kotlin as a first class citizen of the framework.

##Defining the project and dependencies
To get started, we’ll need to add the Gradle dependencies we need for Spring Boot and Kotlin and modify our buildpath.

```
buildscript {  
   ext {
       kotlinVersion = "1.2.30"
       springBootVersion = "1.5.9.RELEASE"
       ...
   }

   repositories {
       jcenter()
   }

   dependencies {
       classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion"
       classpath "org.jetbrains.kotlin:kotlin-noarg:$kotlinVersion"
       classpath "org.jetbrains.kotlin:kotlin-allopen:$kotlinVersion"

       classpath "org.springframework.boot:spring-boot-gradle-plugin:$springBootVersion"
   }
}

dependencies {  
    compile "org.jetbrains.kotlin:kotlin-stdlib-jre8:$kotlinVersion"
    compile "org.jetbrains.kotlin:kotlin-reflect:$kotlinVersion"

    compile "org.springframework.boot:spring-boot-starter-security"
    compile "org.springframework.security.oauth:spring-security-oauth2"
    ...
}

```
We’ll then need to apply the Kotlin and Spring Boot Gradle plugins.

```
apply plugin: "kotlin"  
apply plugin: "kotlin-spring"  
apply plugin: "org.springframework.boot"  
```

##Adding our user definition and logic
We’ll need a data class representing a user account, so let’s create that now.

```
@Entity
@Table(name = "account")
data class Account(@Column(name = "email", nullable = false)  
                   var email: String,

                   @NaturalId
                   @Column(name = "username", unique = true, nullable = false)
                   @NotNull
                   @Size(min = 3, max = 255)
                   var username: String = email,

                   @Size(min = 8)
                   @get:JsonIgnore
                   @set:JsonProperty
                   var password: String? = null,

                   var firstName: String,
                   var lastName: String) {

    @Id
    @GeneratedValue
    var id: Long? = null
}
```

Notice the separation of the `username` and `email` properties. We’ll be supporting user sign-in via third-party OAuth authorization servers so a user's unique username isn't necessarily their email address. Having two separate properties also decouples a user's identity from their email addresses - allowing users to have multiple email addresses. The `password` property is also nullable, as users signing in through third party authentication providers don’t need a password.

To access user entity we’ll be using Spring Data autoconfigured by Spring Boot. This will implement and create an instance of JpaRepository at runtime if we add this:

```
interface AccountRepository : JpaRepository<Account, Long> {  
    fun findByUsername(username: String): Account?
}
```

Spring also expects an instance of `UserDetailsService` to pull our user details into the security context. We’ll implement that via

```
@Service
@Transactional
class AccountServiceImpl(private val oAuthAccountDetailWriterFactory: OAuthAccountDetailWriterFactory,  
                         private val accountRepository: AccountRepository) : AccountService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        val account = accountRepository.findByUsername(username)
                ?: throw UsernameNotFoundException("Could not find account with username $username!")


        return with(account) {
            User.withUsername(username)
                    .password(password)
                    .authorities("USER")
                    .build()
        }
    }

    override fun saveOAuth2Account(oAuth2Authentication: OAuth2Authentication): Account {
        val userAuthentication = oAuth2Authentication.userAuthentication
        val details = userAuthentication.details as Map<*, *>
        val accountWriter = oAuthAccountDetailWriterFactory
                .getAccountDetailWriter(oAuth2Authentication.oAuth2Request.clientId)
        val username = userAuthentication.principal as String

        return accountRepository.findByUsername(username)
                ?: accountRepository.save(accountWriter.createAccount(username, details))
    }
}
```

`AccountServiceImpl` implements `AccountService` which extends Spring's `UserDetailsService` and adds a function `saveOAuth2Account(oAuth2Authentication: OAuth2Authentication)`, responsible for intercepting OAuth authentication via third party authorization services to create or update user accounts for our service. `UserDetailsService` defines a single function: `loadUserByUsername(username: String)`, which is responsible for getting a user's login information from our service to be used by Spring Security to authenticate the user. For users signing in through a username and password, we simply check the `AccountRepository` for a user with such a username and return their password, granted authorities (to determine additional permissions), and optionally additional user details. If no such user exists, we throw a `UsernameNotFoundException`.

Now that we have the user logic implemented, let’s look to configuring our Spring Boot application as an authorization server!

##Configuring the authorization server
We'll have to apply the `@EnableAuthorizationServer` annotation to our application. This tells Spring Boot to enable its OAuth 2.0 Authorization Server mechanism.

```
@Configuration
@EnableAuthorizationServer
class AuthorizationServerConfiguration(private val authenticationManager: AuthenticationManager, private val dataSource: DataSource)  
: AuthorizationServerConfigurerAdapter() {

    override fun configure(oauthServer: AuthorizationServerSecurityConfigurer) = configure(oauthServer) {
        checkTokenAccess("isAuthenticated()")
    }

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) = configure(endpoints) {
        authenticationManager(authenticationManager)
        tokenStore(tokenStore())
    }

    override fun configure(clients: ClientDetailsServiceConfigurer) = configure(clients) {
        jdbc(dataSource)
    }

    @Bean
    @Primary
    fun tokenServices() = DefaultTokenServices().apply {
        setTokenStore(tokenStore())
        setSupportRefreshToken(true)
    }

    @Bean
    fun tokenStore() = JdbcTokenStore(dataSource)
}
```

We only allow access to the `/oauth/check_token` if the requesting agent is authenticated. Note the `configure` function acts with its argument as the [function receiver](https://blog.kotlin-academy.com/programmer-dictionary-function-literal-with-receiver-vs-function-type-with-receiver-cc21dba0f4ff), so the call to `checkTokenAccess("isAuthenticated()")` acts on the `oauthServer` object.

`AuthorizationServerConfiguration` also configures a `JdbcTokenStore` as we're choosing to use a SQL datasource to store our tokens in this example. We can configure a variety of token stores, for example using Redis or an in-memory store, but in this example we've chosen to use H2. `setSupportRefreshToken(true)` allows us to create OAuth V2 refresh tokens. Since our access tokens are short-lived (lasting a day), this allows applications to refresh their access tokens without any user interaction, meaning we can benefit from the reduced risk of an access token being compromised but still allow automated processes to re-authorize without user's sharing their password.

In this example, to demonstrate our server's support for delegated authentication, we'll be allowing users to authenticate via Facebook and Google accounts. To do this, we'll take advantage of Spring Security OAuth2 supports for the OAuth client flow. This means our authorization server itself acts as an OAuth client application, requesting Facebook and Google access tokens and using those tokens to issue its own tokens; in addition to the password login flow. In `WebSecurityConfiguration` we apply the `@EnableOAuth2Client` annotation.

```
@Configuration
@EnableOAuth2Client
class WebSecurityConfiguration(private val oauth2ClientContext: OAuth2ClientContext,  
                               private val dataSource: DataSource,
                               private val facebookConfig: FacebookConfig,
                               private val googlePlusConfig: GooglePlusConfig,
                               private val accountService: AccountService) : WebSecurityConfigurerAdapter() {

    override fun configure(auth: AuthenticationManagerBuilder) = configure(auth) {
        userDetailsService(accountService).passwordEncoder(BCryptPasswordEncoder())
        jdbcAuthentication().dataSource(dataSource)
    }

    override fun configure(http: HttpSecurity) = configure(http) {
        antMatcher("/**")
                .authorizeRequests().antMatchers("/", "/login**", "/assets/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin().loginPage("/login").permitAll()
                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter::class.java)
    }

    @Bean
    fun oauth2ClientFilterRegistration(filter: OAuth2ClientContextFilter) = FilterRegistrationBean().apply {
        this.filter = filter
        order = -100
    }

    private fun ssoFilter() = CompositeFilter().apply {
        val facebookFilter = facebookConfig.filter("/login/facebook") { userId -> "$userId@facebook.com" }
        val googlePlusFilter = googlePlusConfig.filter("/login/google_plus") { userId -> "$userId@google.com" }

        setFilters(listOf(facebookFilter, googlePlusFilter))
    }

    private fun ClientResources.filter(path: String, usernameMapper: (String) -> String) = OAuth2ClientAuthenticationProcessingFilter(path).apply {
        val template = OAuth2RestTemplate(this@filter.client, oauth2ClientContext)

        setRestTemplate(template)
        setTokenServices(UserInfoTokenServices(this@filter.resource.userInfoUri, 
                        this@filter.client.clientId).apply {
            setRestTemplate(template)
            setPrincipalExtractor(OAuth2PrincipalExtractor(usernameMapper))
        })
        setAuthenticationSuccessHandler(OAuth2SsoAuthenticationSuccessHandler(accountService))
    }
}
```

Since we're extending `WebSecurityConfigurerAdapter`, let's use this chance to register our `AccountService` instance as a `UserDetailsService` to load our user data into the Spring context. We shouldn't store passwords in plain text, for a whole bunch of reasons, so we'll also set a `PasswordEncoder` for Spring to use to check hashed passwords when users sign in via their passwords.

##Using the authorization server
OAuth V2 defines a few different authorization flows. To test our authorization server, we'll be using the authorization code flow. This three-legged flow works best for web apps running on a backend server, capable of hiding secrets. This is considered the safest choice as both the user and your application prove themselves to the authorization server, unlike the implicit flow where it is [possible for an attacker to steal tokens](https://medium.com/@justinsecurity/mobile-apps-and-oauths-implicit-flow-68e72c6515a1) without having to compromise your network.

To begin the authorization `code` flow, let's first redirect the user to our login page with the OAuth authorize endpoint, passing in our client application's id and using the code grant: if you're running the sample application, its url looks like this http://localhost:8080/oauth/authorize?response_type=code&client_id=client_app_id&redirect_uri=http://example.com

We've set `redirect_uri` to http://example.com for this example: where we can later get an authorization code. In a production application, the `redirect_uri` will be the client application's OAuth callback endpoint.

![](https://raw.githubusercontent.com/venasolutions/sample-authorization-server/master/login.png)

Our authorization server allows the user to sign in natively into the application or by delegating to a third party OAuth provider like Facebook or Google (with the authorization functioning itself as a client application). If the user successfully signs in, their browser is then redirected to the redirect url with an OAuth V2 auth code.

![](https://github.com/venasolutions/sample-authorization-server/raw/master/redirect_auth_code.png)

To complete the last leg of the authorization code flow, this auth code can then be traded for an access token and refresh token via the OAuth token endpoint. You prove your client application's identity authenticating with Basic Authorization using your client ID and client secret. The HTTP body of this request should contain your grant type (authorization_code), client id, the redirect url you acquired the code from, and the code you acquired.

Using cURL:

![](https://github.com/venasolutions/sample-authorization-server/raw/master/token_result.png)

And that’s it! We’ve written a full-fledged authorization server in under an hour, thanks to Spring Boot’s coding by convention approach and Kotlin’s conciseness. We now support the complete standard OAuth V2 protocol, ensuring our users are secured so we can focus on what makes our application special, without the need to reinvent the wheel.

You can find the source code for the working example of this application on [Github](https://github.com/venasolutions/sample-authorization-server), under the [Apache V2](https://github.com/venasolutions/sample-authorization-server/blob/master/LICENSE) license. Happy coding!
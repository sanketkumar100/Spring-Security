## ***JWT implementation:***



&nbsp;	(Note:- the dependency of jwt is not present on spring.io) So,to set the jwt dependency in Maven=> search=jwt GitHub Maven->click on the first link(the official documentation of jwt comes)->scroll down and Find the Implementation part and then click on Maven-> Copy and paste the dependency in pom.xml.



###### **1st)**	Create **"JwtUtils"** class in src/main/java/jwt/jwtutils:

&nbsp;		This class is defined as a @component

**Explanation:**

&nbsp;                @Value("${spring.app.jwtSecret}")  //@value gets the properties from the 		private String jwtSecret;	      application.properties, we can 							define the value here irself but this is 						the good way.

&nbsp;                



&nbsp;               @Value("${spring.app.jwtExpirationMs}")

&nbsp;               private int jwtExpirationMs;

The above are the two variables defined the jwtSecret is used for signing purpose another is used for expiraio time.

Both the variables get the value from the application.properties, So it should be configured:>  like: **spring.app.jwtSecret**=sanket7645#

&nbsp;                  **spring.app.jwtExpirationMs**=300000000000000





&nbsp;	public String getJwtFromHeader(HttpServletRequest request) 

&nbsp;       {

&nbsp;       String bearerToken = request.getHeader("Authorization");// to get the Authorization 								header from the httprequest

&nbsp;       logger.debug("Authorization Header: {}", bearerToken);

&nbsp;       if (bearerToken != null \&\& bearerToken.startsWith("Bearer ")) 

&nbsp;       {

&nbsp;           return bearerToken.substring(7); // Remove Bearer prefix and retuen the token

&nbsp;       }



&nbsp;	return null;

&nbsp;	}

The above methode is defined to get the jwt token form the entire Header.

&nbsp;	Format of the header=> "Authentication: bearer<token>"





&nbsp;	public String generateTokenFromUsername(UserDetails userDetails) 

&nbsp;       {

&nbsp;       String username = userDetails.getUsername();

&nbsp;       return Jwts.builder()

&nbsp;               .subject(username)

&nbsp;               .issuedAt(new Date()) //setting the issue time

&nbsp;               .expiration(new Date((new Date()).getTime() + jwtExpirationMs))  //we are 						      setting expiration here by getting 						the (current time + the expiration time)

&nbsp;               .signWith(key())     //Here we are signing with the key. key() is a method 					which we will define.

&nbsp;               .compact();        //it actually builds the jwt and serializes it to 						compact URL safe string

&nbsp;      }



The above method is used to generate jwts token from the username.

&nbsp;	**Jwts.builder():-**Jwts-> It is a class which is present in the jwts dependency.





&nbsp;		public String getUserNameFromJwtToken(String token) 

&nbsp;               {

&nbsp;                 return Jwts.parser()

&nbsp;                .verifyWith((SecretKey) key())  //verifying

&nbsp;               .build().parseSignedClaims(token)

&nbsp;               .getPayload().getSubject();       //getting the subject from the token 							which is present in the PayLoad. Username 					is stored as subject in the token while creating

&nbsp;               }



By using the above method we are extracting the username from the jwt token or we can say decoding.





&nbsp;		private Key key() 

&nbsp;               {

&nbsp;                  return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

&nbsp;   		}



In the above methode we are setting up the key for signing the token.









&nbsp;	        public boolean validateJwtToken(String authToken) 

&nbsp;               {

&nbsp;                  try 

&nbsp;                    {

&nbsp;                     System.out.println("Validate");

&nbsp;                     Jwts.parser().verifyWith((SecretKey)key()).

&nbsp;                          .build().parseSignedClaims(authToken);

&nbsp;                   return true;

&nbsp;                } catch (MalformedJwtException e) {

&nbsp;                    logger.error("Invalid JWT token: {}", e.getMessage());

&nbsp;                } catch (ExpiredJwtException e) {

&nbsp;                    logger.error("JWT token is expired: {}", e.getMessage());

&nbsp;                } catch (UnsupportedJwtException e) {

&nbsp;                    logger.error("JWT token is unsupported: {}", e.getMessage());

&nbsp;                } catch (IllegalArgumentException e) {

&nbsp;                    logger.error("JWT claims string is empty: {}", e.getMessage());

&nbsp;              }

&nbsp;              return false; //returning false if not valdated

&nbsp;             }









**2nd)**  create a "AuthTokenFilter" class which is our own custom filter, which intercepts the request and validates it with the help of "jwtUtil" class.



**Explanation:**

		

		public class AuthTokenFilter extends OncePerRequestFilter {



//This class extends "OncePerRequestFilter" which makes sure that this particular filter executes only once per request.  It is used when we want to aplly logic or perform operations only once per http request.





&nbsp;		@Autowired

&nbsp;                private JwtUtils jwtUtils;



&nbsp;               @Autowired

&nbsp;                private UserDetailsService userDetailsService;



in the above we are doing Field in jetion and we are autoring tnhe instances.

&nbsp;         jwtutils-> is a component which we already defined, so it wil be autowired.

&nbsp;         userDetailsService-> It is a inbuilt interface









&nbsp;		@Override

&nbsp;               protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)throws ServletException, IOException 

&nbsp;          //the method is overridden and we are getting request,response and filterchain 		as parameter.     

&nbsp;                {

&nbsp;       	logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());

&nbsp;       	try 

&nbsp;                  {

&nbsp;          	    String jwt = parseJwt(request); //calling parsejwt() to extract token 							from header

&nbsp;           	    if (jwt != null \&\& jwtUtils.validateJwtToken(jwt)) //validation process 						starts from here and it is done by using 					the methods which we defined in the JwtUtils class

&nbsp;                   {

&nbsp;                   String username = jwtUtils.getUserNameFromJwtToken(jwt);//method of 									jwtUtils class



&nbsp;                  UserDetails userDetails = userDetailsService.loadUserByUsername(username);//loading the user details based on the 						username which is extracted from the jwt.



&nbsp;                 UsernamePasswordAuthenticationToken authentication =new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities()); //passing the userdetails,credentials and users role i,e, Authorities.

&nbsp;					note: "UsernamePasswordAuthenticationToken" is an 				implementation of Authentication that is used for simple 				presentation of username and password.

&nbsp;                 logger.debug("Roles from JWT: {}", userDetails.getAuthorities()); //just for debugging purpose, it is not compulsory



&nbsp;                 authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); //"authentication" is the token 			which we created above and here, we are creating or building it by 			enhancing the token by 	using the additional details which we are 			getting from the request, like:- ession id etc.



&nbsp;                 SecurityContextHolder.getContext().setAuthentication(authentication); 					//here, we are setting the securityContext to 							effectively authenticate the user for the 						duration of the request.

&nbsp;                 }

&nbsp;               } catch (Exception e) 

&nbsp;                 {

&nbsp;                   logger.error("Cannot set user authentication: {}", e);

&nbsp;                 }



&nbsp;          filterChain.doFilter(request, response);// it says that "hey continue the the 						filter chain as usual" because we have made 						custom filter by overriding.

&nbsp;          }



In the above the "doFilterInternal" method is being overridden, which a method of class "oncePerrequest".







&nbsp;          private String parseJwt(HttpServletRequest request) 

&nbsp;          {

&nbsp;           String jwt = jwtUtils.getJwtFromHeader(request);

&nbsp;          logger.debug("AuthTokenFilter.java: {}", jwt);

&nbsp;          return jwt;

&nbsp;          }

the above method calls getJwtFromHeader() method which we defined in JwtUtils class and gets the token in styring form, then returns it to the overridden doFilterInternal().









**3rd) "AuthEntryPointJwt" class** is invoked when there is any unauthorized request detected, So it provides custom handling for unauthorized request.





&nbsp;	

@Component

public class AuthEntryPointJwt implements AuthenticationEntryPoint   //this class 						implements "AuthenticationEntryPoint" class which 					indicates that this class will provide custom 						handling for authentication related errors.

&nbsp;{



&nbsp;   private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);



&nbsp;   @Override

&nbsp;   public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)throws IOException, ServletException    //overriding                     								the commence() method

&nbsp;   {

&nbsp;       logger.error("Unauthorized error: {}", authException.getMessage());



&nbsp;       response.setContentType(MediaType.APPLICATION\_JSON\_VALUE);

&nbsp;       response.setStatus(HttpServletResponse.SC\_UNAUTHORIZED); //401



&nbsp;       final Map<String, Object> body = new HashMap<>();  //hash map which contains the 							detail of the unauthorized access

&nbsp;       body.put("status", HttpServletResponse.SC\_UNAUTHORIZED);

&nbsp;       body.put("error", "Unauthorized");

&nbsp;       body.put("message", authException.getMessage());

&nbsp;       body.put("path", request.getServletPath());  //url that the user was trying to 								access



&nbsp;       final ObjectMapper mapper = new ObjectMapper();

&nbsp;       mapper.writeValue(response.getOutputStream(), body);//sending the above created 								"body" hashMap as 								response.the hashMap is being 								mapped into Json format and sent

&nbsp;   }



}







**4th) "LoginRequest" class:>** This class is the format which we get for the log-in from the users, So, this is the class which represents the request that we get.



package com.example.securitydemo.jwt;





public class LoginRequest {

&nbsp;   private String username;



&nbsp;   private String password;



&nbsp;   public String getUsername() {

&nbsp;       return username;

&nbsp;   }



&nbsp;   public void setUsername(String username) {

&nbsp;       this.username = username;

&nbsp;   }



&nbsp;   public String getPassword() {

&nbsp;       return password;

&nbsp;   }



&nbsp;   public void setPassword(String password) {

&nbsp;       this.password = password;

&nbsp;   }

}



Note: Instead of getters and setters we can use "Lombok".







**5th)"LoginResponse" class:>** Int this class we send the jwttoken,username and the list of roles as the response, and we can customize this also.





package com.example.securitydemo.jwt;



import java.util.List;



public class LoginResponse {

&nbsp;   private String jwtToken;



&nbsp;   private String username;

&nbsp;   private List<String> roles;



&nbsp;   public LoginResponse(String username, List<String> roles, String jwtToken) {

&nbsp;       this.username = username;

&nbsp;       this.roles = roles;

&nbsp;       this.jwtToken = jwtToken;

&nbsp;   }



&nbsp;   public String getJwtToken() {

&nbsp;       return jwtToken;

&nbsp;   }



&nbsp;   public void setJwtToken(String jwtToken) {

&nbsp;       this.jwtToken = jwtToken;

&nbsp;   }



&nbsp;   public String getUsername() {

&nbsp;       return username;

&nbsp;   }



&nbsp;   public void setUsername(String username) {

&nbsp;       this.username = username;

&nbsp;   }



&nbsp;   public List<String> getRoles() {

&nbsp;       return roles;

&nbsp;   }



&nbsp;   public void setRoles(List<String> roles) {

&nbsp;       this.roles = roles;

&nbsp;   }

}









**6th)"GreetingsController"**





&nbsp;@PostMapping("/signin")

&nbsp;   public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) 									//Loginrequest is the input

&nbsp;  {

&nbsp;       Authentication authentication; //Authenticatiion is the core object of spring 											security

&nbsp;       try {

&nbsp;           authentication = authenticationManager

&nbsp;                   .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));//authentication manager is being used to manage and 					authenticate the user. here, first the token is being 					created by using "UsernamePasswordAuthenticationToken" then 				it is authenticated.

&nbsp;       } catch (AuthenticationException exception) //in case of authentication exception,                   							this response will be thrown

&nbsp;          {

&nbsp;           Map<String, Object> map = new HashMap<>();

&nbsp;           map.put("message", "Bad credentials");

&nbsp;           map.put("status", false);

&nbsp;           return new ResponseEntity<Object>(map, HttpStatus.NOT\_FOUND);

&nbsp;       }



&nbsp;       SecurityContextHolder.getContext().setAuthentication(authentication);//after try 							block , the securityContext will be 						set. It officialy marks that the user is 						authenticated in sptingsecurity Context.



&nbsp;       UserDetails userDetails = (UserDetails) authentication.getPrincipal(); //retrieve 						the user details to generate the jwt.and 						"userdetails is a part security core packg"



&nbsp;       String jwtToken = jwtUtils.generateTokenFromUsername(userDetails); //generating jwt 								token by using jwtutils



&nbsp;       List<String> roles = userDetails.getAuthorities().stream()

&nbsp;               .map(item -> item.getAuthority())

&nbsp;               .collect(Collectors.toList());// getting the roles to pass as he response, 						we can remove it if the roles are not 							required in the response.



&nbsp;       LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken); //creating the Loginresponse object and sending the recquired parameters.



&nbsp;       return ResponseEntity.ok(response); //sending response stats with the object.

&nbsp;   }





**Flow of the above grettingsController:**

i)authentication

ii0if authentication is valid, then set the securityContext and with the help of jwtUtils generate the jwt token.So, jwt token is only generated if the user is authenticated. 





**7th)SecurityConfig:**

  



@Configuration

@EnableWebSecurity

@EnableMethodSecurity

public class SecurityConfig

{

&nbsp;   @Autowired

&nbsp;   DataSource dataSource;



&nbsp;   @Autowired

&nbsp;   private AuthEntryPointJwt unauthorizedHandler;



&nbsp;   @Bean

&nbsp;   public AuthTokenFilter authenticationJwtTokenFilter() {

&nbsp;       return new AuthTokenFilter();

&nbsp;   }



&nbsp;   @Bean

&nbsp;   SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

&nbsp;       http.authorizeHttpRequests(authorizeRequests ->

&nbsp;               authorizeRequests.requestMatchers("/h2-console/\*\*").permitAll()

&nbsp;                       .requestMatchers("/signin").permitAll()

&nbsp;                       .anyRequest().authenticated());// permitting two endpoints 



&nbsp;       http.sessionManagement(

&nbsp;               session ->

&nbsp;                       session.sessionCreationPolicy(

&nbsp;                               SessionCreationPolicy.STATELESS)

&nbsp;       );//marking session as stateless



&nbsp;       http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));//exception handling by using 					"unauthorizedHandler" which is of type "AuthEntryPointJwt"

&nbsp;       //http.httpBasic(withDefaults());

&nbsp;       http.headers(headers -> headers

&nbsp;               .frameOptions(frameOptions -> frameOptions

&nbsp;                       .sameOrigin()

&nbsp;               )

&nbsp;       );

&nbsp;       http.csrf(csrf -> csrf.disable());

&nbsp;       http.addFilterBefore(authenticationJwtTokenFilter(),

&nbsp;               UsernamePasswordAuthenticationFilter.class); //here we have added our 							custom filter in the filter chain. 						"UsernamePasswordAuthenticationFilter" is a inbuilt 						filter so, we have said that before 						executing this execute our custom filter.







&nbsp;       return http.build();//return the security filter chain

&nbsp;   }



&nbsp;   @Bean

&nbsp;   public UserDetailsService userDetailsService()

&nbsp;   {

&nbsp;       UserDetails user1= User.withUsername("user1")

&nbsp;                              .password(passwordEncoder().encode("pass1"))

&nbsp;                              .roles("USER")

&nbsp;                               .build();

&nbsp;       UserDetails admin= User.withUsername("admin")

&nbsp;               .password(passwordEncoder().encode("pass2"))

&nbsp;               .roles("ADMIN")

&nbsp;               .build();



&nbsp;       //To store data in the Database

&nbsp;       JdbcUserDetailsManager userDetailsManager

&nbsp;               =new JdbcUserDetailsManager(dataSource);

&nbsp;       userDetailsManager.createUser(user1);

&nbsp;       userDetailsManager.createUser(admin);

&nbsp;       return userDetailsManager;

&nbsp;       //return new InMemoryUserDetailsManager(user1, admin);

&nbsp;   }



&nbsp;   @Bean

&nbsp;   public PasswordEncoder passwordEncoder()

&nbsp;   {

&nbsp;       return new BCryptPasswordEncoder();

&nbsp;   }



&nbsp;   @Bean

&nbsp;   public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception

&nbsp;   {

&nbsp;       return builder.getAuthenticationManager();

&nbsp;   }

}






























































































































































# spring-security

### 写在前面

##### 基于Session的认证方式

在之前单体架构时代，我们认证成功之后会将信息存在Session中，然后响应给客户端的是对应的Session中的数据的key，客户端会将这个key存储在cookie中，之后的请求都会携带这个cookie中的信息。

![1615721706161](./img/1615721706161.png)

相当于你携带了一张身份证，你每次访问服务器，我只要根据身份证上的信息和服务器后台比对成功，你就可以通过。

但是随着架构的演变，在项目很多的情况下，我们会选择分布式或者前后端分离，这样的情况下session的认证的方式就存在一些问题

* session的跨域问题，和session共享需要解决
* cookie存储的内容大小为4k
* cookie的有效范围是在当前域名下，所以在分布式环境下或者前后端分离的项目中不适用。
* 服务器存储了所有认证过的用户信息，一旦服务器宕机，会丢失所有的用户信息。

#### 基于Token的认证方式

相较于session对需求的兼容，基于Token的方式便是我们在挡下项目中处理认证和授权实现方式的首先了，Token的方式其实就是在用户认证成功后，就把用户的信息通过加密封装到Token中，在响应客户端的时候将Token信息传回客户端，当下一次请求到来的时候，在请求的Http请求head的Authentication中携带token。

![1615722169362](./img/1615722169362.png)

一般来说，token可能还会携带超时时间之间的内容，让用户再次进行登录操作之类的。

由于token里面自带了用户的信息，所以我们可以将原本存储与session的内容压力均摊给客户端，这就相当于服务器发给你一张加密的身份证，类似上班的工作卡，只要你出示这个，你就一定是自己人。

#### SSO 和 OAuth2.0流程

略

#### SpringSecurity介绍

要去理解spring一个组件，我们只需要看看他是如何进入到IOC容器地即可。

我们首先用spring+springmvc+springscurity来看看，他最原始的集成方式是什么。在`SpringSecurityDemo.zip`可以查看更多。

我们先忽略其它的基础配置文件，来看最主要的Security的配置文件和web.xml。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:aop="http://www.springframework.org/schema/aop"
       xmlns:security="http://www.springframework.org/schema/security"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans-4.2.xsd
    http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context-4.2.xsd
    http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop-4.2.xsd
    http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util-4.2.xsd
    http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security-4.2.xsd">

    <!--
        auto-config="true" 表示自动加载SpringSecurity的配置文件
        use-expressions="true" 使用Spring的EL表达式
     -->
    <security:http auto-config="true" use-expressions="true">

        <security:intercept-url pattern="/login.jsp" access="permitAll()"></security:intercept-url>
        <!--<security:intercept-url pattern="/login.do" access="permitAll()"></security:intercept-url>-->

        <!--
            拦截资源
            pattern="/**" 拦截所有的资源
            access="hasAnyRole('role1')" 表示只有role1这个角色可以访问资源
         -->
        <security:intercept-url pattern="/**" access="hasAnyRole('ROLE_USER')"></security:intercept-url>

        <!--
            配置认证信息
             login-page="/login.jsp"  自定义的登录页面
             login-processing-url="/login" security中处理登录的请求
             default-target-url="/home.jsp" 默认的跳转地址
             authentication-failure-url="/failure.jsp" 登录失败的跳转地址

        <security:form-login
            login-page="/login.jsp"
            login-processing-url="/login"
            default-target-url="/home.jsp"
            authentication-failure-url="/failure.jsp"
        />-->
        <!-- 配置退出的登录信息
        <security:logout logout-url="/logout"
                         logout-success-url="/login.jsp" />
        <security:csrf disabled="true"/>-->
    </security:http>

    <!-- 设置认证用户来源  noop：SpringSecurity中默认 密码验证是要加密的  noop表示不加密 -->
    <security:authentication-manager>
        <security:authentication-provider>
            <security:user-service>
                <security:user name="zhang" password="{noop}123" authorities="ROLE_USER"></security:user>
                <security:user name="lisi" password="{noop}123" authorities="ROLE_ADMIN"></security:user>
            </security:user-service>
        </security:authentication-provider>
    </security:authentication-manager>

</beans>

```

`web.xml`

```xml
<!DOCTYPE web-app PUBLIC
        "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
        "http://java.sun.com/dtd/web-app_2_3.dtd" >

<web-app version="2.5" id="WebApp_ID" xmlns="http://java.sun.com/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
 http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd">
  <display-name>Archetype Created Web Application</display-name>

  <!-- 初始化spring容器 -->
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>classpath:applicationContext.xml</param-value>
  </context-param>
  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>

  <!-- post乱码过滤器 -->
  <filter>
    <filter-name>CharacterEncodingFilter</filter-name>
    <filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class>
    <init-param>
      <param-name>encoding</param-name>
      <param-value>utf-8</param-value>
    </init-param>
  </filter>
  <filter-mapping>
    <filter-name>CharacterEncodingFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <!-- 前端控制器 -->
  <servlet>
    <servlet-name>dispatcherServletb</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <!-- contextConfigLocation不是必须的， 如果不配置contextConfigLocation，
    springmvc的配置文件默认在：WEB-INF/servlet的name+"-servlet.xml" -->
    <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>classpath:springmvc.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>dispatcherServletb</servlet-name>
    <!-- 拦截所有请求jsp除外 -->
    <url-pattern>/</url-pattern>
  </servlet-mapping>

  <!-- 配置过滤器链 springSecurityFilterChain名称固定-->
  <filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>


</web-app>
```

首先，我们这个项目并没有配置任何数据库，也没有配置任何其它的界面，现在我们启动项目。可以看到这样的页面。

![1615726690672](./img/1615726690672.png)

默认的用户名是`user`，而密码会在继承了Security模块的启动控制台随机生成一个`UUID`密码，这里springboot的方式，如果是我们这样的案例因为配置了用户名密码，且不加密的情况就是那个的密码。

```xml
<!-- 设置认证用户来源  noop：SpringSecurity中默认 密码验证是要加密的  noop表示不加密 -->
    <security:authentication-manager>
        <security:authentication-provider>
            <security:user-service>
                <security:user name="zhang" password="{noop}123" authorities="ROLE_USER"></security:user>
                <security:user name="lisi" password="{noop}123" authorities="ROLE_ADMIN"></security:user>
            </security:user-service>
        </security:authentication-provider>
    </security:authentication-manager>
```

以上其实就security的大概样子，但是在这里我们有三个东西要讨论。

* 系统启动SpringSecurity做了什么。
* 默认的认证界面是如何出来的
* 默认的认证流程是怎么实现的

不过在此之前，我们需要思考一个问题，既然是权限的认证，当我们请求某一个资源的时候，权限模块会验证我们是否是合法的，如果不合法会让我们进行登录流程，合法就放行。那么这个动作发生在**Filter**也就是过滤器的话是最合适的。

![1615727306318](./img/1615727306318.png)

那么问题又来了，是在哪个Filter发生了权限的认证或者拦截的呢。这个时候我们想到了之前的`web.xml`的配置。

``` xml
<!-- 配置过滤器链 springSecurityFilterChain名称固定-->
  <filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>

```

我们将上面的流程进行修改，其实就变成了这样。

![1615727490319](./img/1615727490319.png)

**注意**，首先这个`DelegatingFilterProxy`的包路径是`org.springframework.web.filter.DelegatingFilterProxy`，也就是说他是spring框架中自带的，而不是SpringSecurity提供的。对于`DelegatingFilterProxy`，我们等会源码分析会详细说明，spring之所以会设计这样一个类，主要是通过spring容器来管理servlet filter的生命周期，还有就是如果filter中需要一些spring容器的实例，可以通过spring直接注入，另外读取一些配置文件的便利操作也刻意通过spring来配置实现。

很明显，现在这个xml文件的配置，利用的就是读取配置文件的操作来使用，并传入了一个不知道有什么意义的名字，`springSecurityFilterChain`。另外需要说明的是`DelegatingFilterProxy`继承自`GenericFilterBean`，在servlet容器启动的时候回执执行`GenericFilterBean`的`init`方法。

```java
public class DelegatingFilterProxy extends GenericFilterBean {
    // ....
｝
```

他的父类也是实现了很多spring内置地接口。

``` java
public abstract class GenericFilterBean implements Filter, BeanNameAware, EnvironmentAware, EnvironmentCapable, ServletContextAware, InitializingBean, DisposableBean {
    //...
    
    public final void init(FilterConfig filterConfig) throws ServletException {
        Assert.notNull(filterConfig, "FilterConfig must not be null");
        // ....
            } catch (BeansException var6) {
                String msg = "Failed to set bean properties on filter '" + filterConfig.getFilterName() + "': " + var6.getMessage();
                this.logger.error(msg, var6);
                throw new NestedServletException(msg, var6);
            }
        }
		// 上面就是自带的初始化流程，这里是GenericFilterBean类留给子类的扩展用的。
        this.initFilterBean();
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Filter '" + filterConfig.getFilterName() + "' configured for use");
        }

    }
    
    //...
}
```

所以我们直接去看`DelegatingFilterProxy`的`initFilterBean`方法。

```java
 protected void initFilterBean() throws ServletException {
        synchronized(this.delegateMonitor) {
            if (this.delegate == null) {
                if (this.targetBeanName == null) {
                    // 这里的过滤器名字是通过父类的init方法，从Filter的init方法FilterConfig内容获得的，这里的名字就是我们之前在xml里面配置的springSecurityFilterChain
                    this.targetBeanName = this.getFilterName();
                }
				// 获取ioc容器
                WebApplicationContext wac = this.findWebApplicationContext();
                if (wac != null) {
                    //这里会获取一个代理进入
                    this.delegate = this.initDelegate(wac);
                }
            }

        }
    }

protected Filter initDelegate(WebApplicationContext wac) throws ServletException {
        String targetBeanName = this.getTargetBeanName();
        Assert.state(targetBeanName != null, "No target bean name set");
    	// 很明显，这里就是一个从ioc容器中获得对象的操作，beanName也说过了，就是springSecurityFilterChain
        Filter delegate = (Filter)wac.getBean(targetBeanName, Filter.class);
    	//如果有生命周期在执行一遍初始化
        if (this.isTargetFilterLifecycle()) {
            delegate.init(this.getFilterConfig());
        }
		//返回对象
        return delegate;
    }
```

我们来通过**debug**来看看，到底从spring容器中获得了什么样的对象。

![1615729424209](./img/1615729424209.png)

所以其实我们在`web.xmlp`里配置的`DelegatingFilterProxy`其实就是帮我们把beanName为`springSecurityFilterChain`其实实际对象叫`FilterChainProxy`的类持有在了成员变量`delegate`中，就是这样一个流程，之后的所有操作都由这个`delegate`执行。

那么我们知道，实现了过滤器的类在请求过来的时候，会执行`doFilter`方法。

```java
// DelegatingFilterProxy.java 
public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Filter delegateToUse = this.delegate;
    // 这个时候已经不为空了。跳过
        if (delegateToUse == null) {
            synchronized(this.delegateMonitor) {
                delegateToUse = this.delegate;
                if (delegateToUse == null) {
                    WebApplicationContext wac = this.findWebApplicationContext();
                    if (wac == null) {
                        throw new IllegalStateException("No WebApplicationContext found: no ContextLoaderListener or DispatcherServlet registered?");
                    }

                    delegateToUse = this.initDelegate(wac);
                }

                this.delegate = delegateToUse;
            }
        }
		// 核心代码
        this.invokeDelegate(delegateToUse, request, response, filterChain);
    }

protected void invokeDelegate(Filter delegate, ServletRequest request, ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    // 我们进入FilterChainProxy的这个方法再看看。
        delegate.doFilter(request, response, filterChain);
    }
```
所以现在的调用步骤到了这里。

![1615730010585](./img/1615730010585.png)

``` java
// FilterChainProxy.java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        boolean clearContext = request.getAttribute(FILTER_APPLIED) == null;
        if (!clearContext) {
            // 进入
            this.doFilterInternal(request, response, chain);
        } else {
            try {
                request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
                this.doFilterInternal(request, response, chain);
            } catch (RequestRejectedException var9) {
                this.requestRejectedHandler.handle((HttpServletRequest)request, (HttpServletResponse)response, var9);
            } finally {
                SecurityContextHolder.clearContext();
                request.removeAttribute(FILTER_APPLIED);
            }

        }
    }

 private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
     // 防火墙操作
        FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest)request);
        HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse)response);
     /* 这里会从这里获得一个过滤器链，这个过滤器链会从请求的路径中匹配
     	需要注意的是，一个SpringSecurity可以存在多个过滤器链表，每个过滤器链表又可以包含
     	多个过滤器
     */
        List<Filter> filters = this.getFilters((HttpServletRequest)firewallRequest);
     // 确实有调用链，就执行。   
     if (filters != null && filters.size() != 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(LogMessage.of(() -> {
                    return "Securing " + requestLine(firewallRequest);
                }));
            }

            FilterChainProxy.VirtualFilterChain virtualFilterChain = new FilterChainProxy.VirtualFilterChain(firewallRequest, chain, filters);
            virtualFilterChain.doFilter(firewallRequest, firewallResponse);
        } else {
            if (logger.isTraceEnabled()) {
                logger.trace(LogMessage.of(() -> {
                    return "No security for " + requestLine(firewallRequest);
                }));
            }
			//否则，执行下一个过滤器。
            firewallRequest.reset();
            chain.doFilter(firewallRequest, firewallResponse);
        }
    }
```

![1615730496298](./img/1615730496298.png)

```java
public interface SecurityFilterChain {
    boolean matches(HttpServletRequest var1);
	// 所以说，每个SecurityFiterChain还可以持有多个Filter
    List<Filter> getFilters();
}
```

![1615730542022](./img/1615730542022.png)

```java
// FilterChainProxy.java
private List<Filter> getFilters(HttpServletRequest request) {
        int count = 0;
        Iterator var3 = this.filterChains.iterator();

        SecurityFilterChain chain;
        do {
            if (!var3.hasNext()) {
                return null;
            }

            chain = (SecurityFilterChain)var3.next();
            if (logger.isTraceEnabled()) {
                ++count;
                logger.trace(LogMessage.format("Trying to match request against %s (%d/%d)", chain, count, this.filterChains.size()));
            }
            //通过 url地路径，来匹配到一个List<Filter>的列表。
        } while(!chain.matches(request));

        return chain.getFilters();
    }
```

![1615730800617](./img/1615730800617.png)

```
https://www.processon.com/view/link/5f7b197ee0b34d0711f3e955#map
这里查看，各个filter的使用。
```

```java
// FilterChainProxy.java
private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest)request);
        HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse)response);
        List<Filter> filters = this.getFilters((HttpServletRequest)firewallRequest);
        if (filters != null && filters.size() != 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(LogMessage.of(() -> {
                    return "Securing " + requestLine(firewallRequest);
                }));
            }

            FilterChainProxy.VirtualFilterChain virtualFilterChain = new FilterChainProxy.VirtualFilterChain(firewallRequest, chain, filters);
            // 进入这里
            virtualFilterChain.doFilter(firewallRequest, firewallResponse);
        } else {
            if (logger.isTraceEnabled()) {
                logger.trace(LogMessage.of(() -> {
                    return "No security for " + requestLine(firewallRequest);
                }));
            }

            firewallRequest.reset();
            chain.doFilter(firewallRequest, firewallResponse);
        }
    }
// 内部类 VirtualFilterChain
public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
    		// 看看是否已经迭代到了底。
            if (this.currentPosition == this.size) {
                if (FilterChainProxy.logger.isDebugEnabled()) {
                    FilterChainProxy.logger.debug(LogMessage.of(() -> {
                        return "Secured " + FilterChainProxy.requestLine(this.firewalledRequest);
                    }));
                }

                this.firewalledRequest.reset();
                // 走原来的链流程。
                this.originalChain.doFilter(request, response);
            } else {
                // 否则走链的过滤器逻辑
                ++this.currentPosition;
                Filter nextFilter = (Filter)this.additionalFilters.get(this.currentPosition - 1);
                if (FilterChainProxy.logger.isTraceEnabled()) {
                    FilterChainProxy.logger.trace(LogMessage.format("Invoking %s (%d/%d)", nextFilter.getClass().getSimpleName(), this.currentPosition, this.size));
                }
				// 责任链逻辑的体现，也就是我们接下来需要讨论的15个过滤器中的具体作用。
                nextFilter.doFilter(request, response, this);
            }
        }
```

##### ExceptionTranslationFilter

![1615731620941](./img/1615731620941.png)

作为了倒数第二的过滤器，我们来看看他的doFilter做了些什么。

```java
private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    	    
    try {
            //进入了下一个过滤器进行执行 FilterSecurityInterceptor
            chain.doFilter(request, response);
        } catch (IOException var7) {
            throw var7;
        } catch (Exception var8) {
        	// FilterSecurityInterceptor 抛出了异常，这里处理。
            Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(var8);
            RuntimeException securityException = (AuthenticationException)this.throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);
            if (securityException == null) {
                securityException = (AccessDeniedException)this.throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
            }

            if (securityException == null) {
                this.rethrow(var8);
            }

            if (response.isCommitted()) {
                throw new ServletException("Unable to handle the Spring Security Exception because the response is already committed.", var8);
            }
			// 进去
            this.handleSpringSecurityException(request, response, chain, (RuntimeException)securityException);
        }

    }

 private void handleSpringSecurityException(HttpServletRequest request, HttpServletResponse response, FilterChain chain, RuntimeException exception) throws IOException, ServletException {
        if (exception instanceof AuthenticationException) {
            this.handleAuthenticationException(request, response, chain, (AuthenticationException)exception);
        } else if (exception instanceof AccessDeniedException) {
            this.handleAccessDeniedException(request, response, chain, (AccessDeniedException)exception);
        }

    }

    private void handleAuthenticationException(HttpServletRequest request, HttpServletResponse response, FilterChain chain, AuthenticationException exception) throws ServletException, IOException {
        this.logger.trace("Sending to authentication entry point since authentication failed", exception);
        // 进入
        this.sendStartAuthentication(request, response, chain, exception);
    }

    private void handleAccessDeniedException(HttpServletRequest request, HttpServletResponse response, FilterChain chain, AccessDeniedException exception) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAnonymous = this.authenticationTrustResolver.isAnonymous(authentication);
        if (!isAnonymous && !this.authenticationTrustResolver.isRememberMe(authentication)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Sending %s to access denied handler since access is denied", authentication), exception);
            }

            this.accessDeniedHandler.handle(request, response, exception);
        } else {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Sending %s to authentication entry point since access is denied", authentication), exception);
            }
			// 进入
            this.sendStartAuthentication(request, response, chain, new InsufficientAuthenticationException(this.messages.getMessage("ExceptionTranslationFilter.insufficientAuthentication", "Full authentication is required to access this resource")));
        }

    }

protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, AuthenticationException reason) throws ServletException, IOException {
        SecurityContextHolder.getContext().setAuthentication((Authentication)null);
        this.requestCache.saveRequest(request, response);
        // 进入
    	this.authenticationEntryPoint.commence(request, response, reason);
    }
```

![1615732240889](./img/1615732240889.png)

```java
// 这里基本都是跳转的到登陆页面的逻辑了。
public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String redirectUrl;
        if (!this.useForward) {
            // http://localhost:8080/login
            // 如果是重定向 302，那么就会被DefaultLoginPageGeneratingFilter过滤器拦截，因为他默认会拦截/login的请求，进行认证。
            redirectUrl = this.buildRedirectUrlToLoginPage(request, response, authException);
            this.redirectStrategy.sendRedirect(request, response, redirectUrl);
        } else {
            redirectUrl = null;
            if (this.forceHttps && "http".equals(request.getScheme())) {
                redirectUrl = this.buildHttpsRedirectUrlForRequest(request);
            }

            if (redirectUrl != null) {
                this.redirectStrategy.sendRedirect(request, response, redirectUrl);
            } else {
                String loginForm = this.determineUrlToUseForThisRequest(request, response, authException);
                logger.debug(LogMessage.format("Server side forward to: %s", loginForm));
                RequestDispatcher dispatcher = request.getRequestDispatcher(loginForm);
                dispatcher.forward(request, response);
            }
        }
    }
```

##### FilterSecurityInterceptor

作为最后的过滤器，也就是做权限的认证，如果有问题，就会抛出异常，被上一个ExceptionTrasalatingFIlter捕获，并做相应的登录处理。

```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        this.invoke(new FilterInvocation(request, response, chain));
    }

    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        if (this.isApplied(filterInvocation) && this.observeOncePerRequest) {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        } else {
            if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
                filterInvocation.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }

            InterceptorStatusToken token = super.beforeInvocation(filterInvocation);

            try {
                filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            } finally {
                super.finallyInvocation(token);
            }
			// 进入父类，AbstractSecurityInterceptor.java
            super.afterInvocation(token, (Object)null);
        }
    }
// AbstractSecurityInterceptor.java
protected Object afterInvocation(InterceptorStatusToken token, Object returnedObject) {
        if (token == null) {
            return returnedObject;
        } else {
            this.finallyInvocation(token);
            if (this.afterInvocationManager != null) {
                try {
                    //进行认证
                    returnedObject = this.afterInvocationManager.decide(token.getSecurityContext().getAuthentication(), token.getSecureObject(), token.getAttributes(), returnedObject);
                } catch (AccessDeniedException var4) {
                    // 并发布事件
                    this.publishEvent(new AuthorizationFailureEvent(token.getSecureObject(), token.getAttributes(), token.getSecurityContext().getAuthentication(), var4));
                    throw var4;
                }
            }

            return returnedObject;
        }
    }
```

##### DefaultLoginPageGeneratingFilter

经过验证失败，要重新跳转到登陆页面的时候，会被这个拦截器拦截下来。

这是他的初始化的时候，我们很明显的可以看出来，他内置的路径。

```
private void init(UsernamePasswordAuthenticationFilter authFilter, AbstractAuthenticationProcessingFilter openIDFilter) {
    this.loginPageUrl = "/login";
    this.logoutSuccessUrl = "/login?logout";
    this.failureUrl = "/login?error";
    if (authFilter != null) {
        this.initAuthFilter(authFilter);
    }

    if (openIDFilter != null) {
        this.initOpenIdFilter(openIDFilter);
    }

}
```

而对应的doFilter方法，则让我们看到了登陆页面到底是如何构成的。

```java
 private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        boolean loginError = this.isErrorPage(request);
        boolean logoutSuccess = this.isLogoutSuccess(request);
        if (!this.isLoginUrlRequest(request) && !loginError && !logoutSuccess) {
            chain.doFilter(request, response);
        } else {
            // 构建登陆界面的html页面，会通过response回写回去。
            String loginPageHtml = this.generateLoginPageHtml(request, loginError, logoutSuccess);
            response.setContentType("text/html;charset=UTF-8");
            response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
            response.getWriter().write(loginPageHtml);
        }
    }
```

我们通过控制台，确实发现，请求了两次。第一次重定向，第二次是真正的html页面。

![1615733349347](./img/1615733349347.png)

完整流程的概括。

![1615733445236](./img/1615733445236.png)

#### 从SpringBoot去理解

前面弄明白了基于xml中的DelegatingFilterProxy来初始化spring-security，接下从springboot中来看看他是如何集成到springboot中去的。

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

首先，基于springboot自动状态要整合第三方框架需要在spring.factories，但是奇怪的是自动装配的配置并不在spring-security的`META-INF`包下，而是在spring的autoconfigure包下。

![1615901579501](./img/1615901579501.png)

```properties
org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,\
org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration,\
org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration,\
```

这三个中和DelegatingFilterProxy有关系的是第三个 SecurityFilterAutoConfiguration 所以我们 就直接先来看这个，其他两个我们后面再分析 

```java
/** *proxyBeanMethods = true 或不写，是Full模式 *proxyBeanMethods = false 是lite模式 * Full模式下通过方法调用指向的仍旧是原来的Bean *Spring 5.2.0+的版本，建议你的配置类均采用Lite模式去做，即显示设置proxyBeanMethods = false。Spring *Boot在2.2.0版本（依赖于Spring 5.2.0）起就把它的所有的自动配置类的此属性改为 了false，即*@Configuration(proxyBeanMethods = false)，提高Spring启动速度 */@Configuration( proxyBeanMethods = false )
// 当前系统的类型为servlet类型 
@ConditionalOnWebApplication( type = Type.SERVLET )
// 放开属性配置 
@EnableConfigurationProperties({SecurityProperties.class}) /* 当前类加载的条件 */
@ConditionalOnClass({AbstractSecurityWebApplicationInitializer.class, SessionCreationPolicy.class}) 
/* 当前类的加载必须是在 SecurityAutoConfiguration 加载完成之后*/
@AutoConfigureAfter({SecurityAutoConfiguration.class}) 
public class SecurityFilterAutoConfiguration { 
    // 默认的过滤器名称 和之前的 web.xml 中个FilterName是一样的 
    private static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain"; 
    public SecurityFilterAutoConfiguration() { 
    }
    @Bean @ConditionalOnBean(name = {"springSecurityFilterChain"} )
    public DelegatingFilterProxyRegistrationBean securityFilterChainRegistration(SecurityProperties securityProperties) {
        DelegatingFilterProxyRegistrationBean registration = new DelegatingFilterProxyRegistrationBean("springSecurityFilterChain", new ServletRegistrationBean[0]);
        registration.setOrder(securityProperties.getFilter().getOrder());
        registration.setDispatcherTypes(this.getDispatcherTypes(securityProperties));
        return registration;
    }
```

##### DelegatingFilterProxyRegistrationBean

`DelegatingFilterProxyRegistrationBean`其实是SpringBoot中为我们添加到**Filter到Spring容器中所扩展的一种方式**。

类图如下。

![1615902288573](./img/1615902288573.png)

```java
@FunctionalInterface
public interface ServletContextInitializer {
    void onStartup(ServletContext servletContext) throws ServletException;
}
//我们进入其子类RegistrationBean中，并查看他的onStartup方法。
public final void onStartup(ServletContext servletContext) throws ServletException {
        String description = this.getDescription();
        if (!this.isEnabled()) {
            logger.info(StringUtils.capitalize(description) + " was not registered (disabled)");
        } else {
            // 进入
            this.register(description, servletContext);
        }
    }

// DynamicRegistrationBean.java
protected final void register(String description, ServletContext servletContext) {
    // 这里会添加对应的过滤器，也就是 DelegatingFilterProxy，我们进去
        D registration = this.addRegistration(description, servletContext);
        if (registration == null) {
            logger.info(StringUtils.capitalize(description) + " was not registered (possibly already registered?)");
        } else {
            this.configure(registration);
        }
    }
// AbstractFilterRegistrationBean.java
 protected Dynamic addRegistration(String description, ServletContext servletContext) {
     //	进入
        Filter filter = this.getFilter();
     // 该过滤器会被添加到servletContext容器中，那么当有满足添加的请求到来的时候就会触发该过滤 器拦截
        return servletContext.addFilter(this.getOrDeduceName(filter), filter);
    }

//DelegatingFilterProxyRegistrationBean.java
public DelegatingFilterProxy getFilter() {
    // 其实就是将 DelegatingFilterProxy 添加了Servlet的过滤器中
        return new DelegatingFilterProxy(this.targetBeanName, this.getWebApplicationContext()) {
            protected void initFilterBean() throws ServletException {
            }
        };
    }
```

至此，我们知道了其实也就是将DelegatingFilterProxy塞进了Servlet的过滤器列表中，然后我们进入他的下一步配置，看他又做了什么。

```java
protected final void register(String description, ServletContext servletContext) {
    // new 了一个DelegatingFilterProxy 进Servlet过滤器列表中
        D registration = this.addRegistration(description, servletContext);
        if (registration == null) {
            logger.info(StringUtils.capitalize(description) + " was not registered (possibly already registered?)");
        } else {
            // 注意这个方法我们要进入AbstractFilterRegistrationBean中查看
            this.configure(registration);
        }
    }
// AbstractFilterRegistrationBean
protected void configure(Dynamic registration) {
        super.configure(registration);
        // ....
        servletNames.addAll(this.servletNames);
        if (servletNames.isEmpty() && this.urlPatterns.isEmpty()) {
            // 如果没有指定对应的servletNames和urlPartterns的话就使用默认的名称和拦截地址 /*
            registration.addMappingForUrlPatterns(dispatcherTypes, this.matchAfter, DEFAULT_URL_MAPPINGS);
        } else {
            if (!servletNames.isEmpty()) {
                registration.addMappingForServletNames(dispatcherTypes, this.matchAfter, StringUtils.toStringArray(servletNames));
            }

            if (!this.urlPatterns.isEmpty()) {
                registration.addMappingForUrlPatterns(dispatcherTypes, this.matchAfter, StringUtils.toStringArray(this.urlPatterns));
            }
        }

    }
// 默认的配置
public abstract class AbstractFilterRegistrationBean<T extends Filter> extends DynamicRegistrationBean<Dynamic> {
    private static final String[] DEFAULT_URL_MAPPINGS = new String[]{"/*"};
    // ....
}
```

至此我们看到了在SpringBoot中是通过DelegatingFilterProxyRegistrationBean 帮我们创建了一个 

DelegatingFilterProxy过滤器并且指定了拦截的地址，默认是 /* ,之后的逻辑就和前面介绍的XML中的 

就是一样的了，请求会进入FilterChainProxy中开始处理。

##### SpringSecurity 的初始化到底经历了什么

我们上面主要是DelegatingFilterProxy，这是xml的主要入口，以及DelegatingFilterProxyRegistratinBean，这是搜springboot的入口。

通过对 第一次请求的流程梳理 我们会有一些疑问就是 FilterChainProxy 是在哪创建的，默认的过滤 

器链和过滤器是怎么来的，这节课我们就详细的来看看在SpringSecurity初始化的时候到底做了哪些事 

情， 

 基于XML的初始化阶段其实就是各种解析器对标签的解析，过程比较繁琐这里我们就不去分析了，我 

们直接在SpringBoot项目中来分析，在SpringBoot项目中分析SpringSecurity的初始化过程显然我们需 

要从 spring.factories 中的SecurityAutoConfiguration开始 

![1616421975559](./img/1616421975559.png)

``` java
@Configuration(
    proxyBeanMethods = false
)
@ConditionalOnClass({DefaultAuthenticationEventPublisher.class})
@EnableConfigurationProperties({SecurityProperties.class})
@Import({SpringBootWebSecurityConfiguration.class, WebSecurityEnablerConfiguration.class, SecurityDataConfiguration.class})
public class SecurityAutoConfiguration {
    public SecurityAutoConfiguration() {
    }
	// 定义了一个默认的事件发布器，从类名上来看，应该是一个权限事件发布器
    // 当容器里没有AuthenticationEventPublisher或者其子类的时候，不装载下面这个类
    @Bean
    @ConditionalOnMissingBean({AuthenticationEventPublisher.class})
    public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }
}
```

该类引入了 `SpringBootWebSecurityConfiguration` ,`WebSecurityEnablerConfiguration`，`SecurityDataConfiguration` 这三个类，那么我们要分析的话就应该接着来看这三个类

##### SpringBootWebSecurityConfiguration

```java
@Configuration(
    proxyBeanMethods = false
)
@ConditionalOnDefaultWebSecurity
@ConditionalOnWebApplication(
    type = Type.SERVLET
)
class SpringBootWebSecurityConfiguration {
    SpringBootWebSecurityConfiguration() {
    }

    @Bean
    @Order(2147483642)
    static class DefaultCOnfigurerAdapter extends WebSecurityConfigurerAdapter{
    DefaultConfigurerAdapter(){
    
    }
    }
}
```

这个配置的作用是在如果开发者没有自定义 WebSecurityConfigurerAdapter 的话，这里提供一个默认 

的实现。 `@ConditionalOnMissingBean({WebSecurityConfigurerAdapter.class})` 如果有自定义的 

WebSecurityConfigurerAdapter那么这个配置也就不会起作用了 

##### WebSecurityEnablerConfiguration

这个配置是 Spring Security 的核心配置，我们需要重点来分析下。

```java
@Configuration(
    proxyBeanMethods = false
)
@ConditionalOnMissingBean(
    name = {"springSecurityFilterChain"}
)
@ConditionalOnClass({EnableWebSecurity.class})
@ConditionalOnWebApplication(
    type = Type.SERVLET
)
@EnableWebSecurity
class WebSecurityEnablerConfiguration {
    WebSecurityEnablerConfiguration() {
    }
}
```

我们看到了熟悉`springSecurityFilterChain`，当容器中没有`springSecurityFilterChain`，这个会被装配、的最关键的就是@EnableWebSecurity注解了

```java
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({WebSecurityConfiguration.class, SpringWebMvcImportSelector.class, OAuth2ImportSelector.class, HttpSecurityConfiguration.class})
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {
    boolean debug() default false;
}
```

在这个接口中我们看到做的事情还是蛮多的，导入了三个类型和一个@EnableGlobalAuthentication 

注解，我们需要重点来看下WebSecurityConfiguration配置类和@EnableGlobalAuthentication注解

##### WebSecurityConfiguration

```java
 @Bean(name = {"springSecurityFilterChain"})
    public Filter springSecurityFilterChain() throws Exception {
        boolean hasConfigurers = this.webSecurityConfigurers != null && !this.webSecurityConfigurers.isEmpty();
        boolean hasFilterChain = !this.securityFilterChains.isEmpty();
        Assert.state(!hasConfigurers || !hasFilterChain, "Found WebSecurityConfigurerAdapter as well as SecurityFilterChain. Please select just one.");
        if (!hasConfigurers && !hasFilterChain) {
            WebSecurityConfigurerAdapter adapter = (WebSecurityConfigurerAdapter)this.objectObjectPostProcessor.postProcess(new WebSecurityConfigurerAdapter() {
            });
            this.webSecurity.apply(adapter);
        }

        //.....
			// 这个地方获取的就是 FilterChainProxy，该对象会被保存到IOC容器中，且name为springSecurityFlterChain
        	// 这里的构建
            return (Filter)this.webSecurity.build();
        }
    }

// 进入到WebSecurity的performBuild
protected Filter performBuild() throws Exception {
        int chainSize = this.ignoredRequests.size() + this.securityFilterChainBuilders.size();
        List<SecurityFilterChain> securityFilterChains = new ArrayList(chainSize);
        Iterator var3 = this.ignoredRequests.iterator();

        while(var3.hasNext()) {
            RequestMatcher ignoredRequest = (RequestMatcher)var3.next();
            securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest, new Filter[0]));
        }

        FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
        if (this.httpFirewall != null) {
            filterChainProxy.setFirewall(this.httpFirewall);
        }

        if (this.requestRejectedHandler != null) {
            filterChainProxy.setRequestRejectedHandler(this.requestRejectedHandler);
        }

        filterChainProxy.afterPropertiesSet();
        Filter result = filterChainProxy;
        if (this.debugEnabled) {
         // ...
		// 这里可以看出，确实返回的是FilterChainProxy，具体构造细节，我会在HttpSecurity中详细解说。
        this.postBuildAction.run();
        return (Filter)result;
    }
```

##### SecurityDataConfiguration

和SpringData有关，现在用到的比较少我们就不去分析它了。

##### UserDetailServiceAutoConfiguration

![1616423652313](./img/1616423652313.png)

其实带有UserService下方的子类，都是和数据打交道的，一般从UserService中获取权限的信息和角色的信息等，而UserService的具体实现和持久化技术息息相关，至于你希望用什么去实现，看具体需求。

```java
@Configuration(
    proxyBeanMethods = false
)
@ConditionalOnClass({AuthenticationManager.class})
@ConditionalOnBean({ObjectPostProcessor.class})
@ConditionalOnMissingBean(
    value = {AuthenticationManager.class, AuthenticationProvider.class, UserDetailsService.class},
    type = {"org.springframework.security.oauth2.jwt.JwtDecoder", "org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector"}
)
public class UserDetailsServiceAutoConfiguration {
    private static final String NOOP_PASSWORD_PREFIX = "{noop}";
    private static final Pattern PASSWORD_ALGORITHM_PATTERN = Pattern.compile("^\\{.+}.*$");
    private static final Log logger = LogFactory.getLog(UserDetailsServiceAutoConfiguration.class);

    public UserDetailsServiceAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean(
        type = {"org.springframework.security.oauth2.client.registration.ClientRegistrationRepository"}
    )
    @Lazy
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties, ObjectProvider<PasswordEncoder> passwordEncoder) {
        User user = properties.getUser();
        List<String> roles = user.getRoles();
        // 使用内存的方式，存储信息，UserDetail在springSecurity代表用户，后面是密码的生成方式
        return new InMemoryUserDetailsManager(new UserDetails[]{org.springframework.security.core.userdetails.User.withUsername(user.getName()).password(this.getOrDeducePassword(user, (PasswordEncoder)passwordEncoder.getIfAvailable())).roles(StringUtils.toStringArray(roles)).build()});
    }

    private String getOrDeducePassword(User user, PasswordEncoder encoder) {
        String password = user.getPassword();
        if (user.isPasswordGenerated()) {
            logger.info(String.format("%n%nUsing generated security password: %s%n", user.getPassword()));
        }

        return encoder == null && !PASSWORD_ALGORITHM_PATTERN.matcher(password).matches() ? "{noop}" + password : password;
    }
}

// SecurityProperties.java
public static class User {
        private String name = "user";
    // uuid生成的密码
        private String password = UUID.randomUUID().toString();
        private List<String> roles = new ArrayList();
```

其实就是生成了一个默认的账号密码配置，你可以通过实现自己的UserDetialService来覆盖系统内部的实现。

##### 初始化地一些小总结

其实就是通过WebSecurityConfiguration和UserDetailServiceAutoConfiguration来初始化，这两个是比较关键的，前者构造了名字为FilterChainPorxy的过滤器链路，后者构建了一个内存中的初始账号信息供我们验证。

#### 深入理解SecurityConfigurer

在`springsecurity`中，有很多的尾缀带有`configurer`的对象，他也是在Security中一个很重要的组成部分，每一个SecurityConfigurer实现都会从中创建一个Filter对象，也就是我们熟悉的过滤器，并初始化到我们之前说得FilterChainProxy对象中的过滤器列表中。

```java
public interface SecurityConfigurer<O, B extends SecurityBuilder<O>> {
    /**
    初始化的方法
    */
    void init(B builder) throws Exception;

    /**
    配置的方法
    */
    void configure(B builder) throws Exception;
}
```

这里还有一个对象叫做，SecurityBuilder，这个其实就是我们熟悉的HttpSecurity，他的主要作用就是为了来构建过滤器链的，也是建造者模式的一种体现。

在init方法和configure方法中的形参都是SecurityBuilder类型，而SecurityBuilder是用来构建过滤器链的`DefaultSecurityFilterChainProxy`

![1616503373334](./img/1616503373334.png)

我们可以发现，Configurer的实现其实有很多，我们不妨随便进一个Configurer中看看，子类的实现到底做了什么，以`CsrfConfigurer`为例子。这个过滤器是为了防止跨域攻击的为准备的类

CsrfConfigurer没有实现init方法，同时他的祖父类(父类的父类)`SecurityConfigurerAdapter`也是一个空实现。说明这个类的初始化的时候并没有做什么特别的事情。

但是在configure中做的事情就有了。

```java
public void configure(H http) {
    // 这里就很明显了，直接New了一个过滤器，里面传入了跨域攻击的所需要的验证token生成类
        CsrfFilter filter = new CsrfFilter(this.csrfTokenRepository);
    // 请求的拦截匹配对象
        RequestMatcher requireCsrfProtectionMatcher = this.getRequireCsrfProtectionMatcher();
    // 存在，则进行拦截处理
        if (requireCsrfProtectionMatcher != null) {
            filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
        }

        AccessDeniedHandler accessDeniedHandler = this.createAccessDeniedHandler(http);
        if (accessDeniedHandler != null) {
            filter.setAccessDeniedHandler(accessDeniedHandler);
        }
		// 获得登出的过滤器，builder中很有很多的Configurer配置信息，可以从这里面取出。
        LogoutConfigurer<H> logoutConfigurer = (LogoutConfigurer)http.getConfigurer(LogoutConfigurer.class);
        if (logoutConfigurer != null) {
            logoutConfigurer.addLogoutHandler(new CsrfLogoutHandler(this.csrfTokenRepository));
        }

        SessionManagementConfigurer<H> sessionConfigurer = (SessionManagementConfigurer)http.getConfigurer(SessionManagementConfigurer.class);
        if (sessionConfigurer != null) {
            sessionConfigurer.addSessionAuthenticationStrategy(this.getSessionAuthenticationStrategy());
        }
		// 将过滤器放到 IOC容器中
        filter = (CsrfFilter)this.postProcess(filter);
    	// 增加到过滤器链中。
        http.addFilter(filter);
    }
```

大致了解SecurityConfigurer做了什么，我们来看看几个比较关键的实现类。

> SecurityConfigurerAdapter
>
> GlobalAuthenticationConfigurerAdapter
>
> WebSecurityConfigurer

![1616504285110](./img/1616504285110.png)

##### SecurityConfigurerAdapter

SecurityConfigurerAdapter 实现了 SecurityConfigurer 接口，我们所使用的大部分的 xxxConfigurer 也都是 SecurityConfigurerAdapter 的子类。 SecurityConfigurerAdapter 在 SecurityConfigurer 的基础上，还扩展出来了几个非常好用的方法 

```java
public abstract class SecurityConfigurerAdapter<O, B extends SecurityBuilder<O>> implements SecurityConfigurer<O, B> {
    private B securityBuilder;
    // 一个用于将不受IOC容器管理的对象放入IOC容器的成员。
    private SecurityConfigurerAdapter.CompositeObjectPostProcessor objectPostProcessor = new SecurityConfigurerAdapter.CompositeObjectPostProcessor();

    public SecurityConfigurerAdapter() {
    }
	// 空实现
    public void init(B builder) throws Exception {
    }
	// 空实现
    public void configure(B builder) throws Exception {
    }
	// 链式变成，再次获的建造者对象，即 SecurityBuilder的实现
    public B and() {
        return this.getBuilder();
    }

    protected final B getBuilder() {
        Assert.state(this.securityBuilder != null, "securityBuilder cannot be null");
        return this.securityBuilder;
    }

    protected <T> T postProcess(T object) {
        return this.objectPostProcessor.postProcess(object);
    }
	
    // 将多个后置处理器集中起来管理，每个后置处理器都可以将不被IOC容器管理的对象，再次管理起来。
    public void addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
        this.objectPostProcessor.addObjectPostProcessor(objectPostProcessor);
    }

    public void setBuilder(B builder) {
        this.securityBuilder = builder;
    }
	
    // 一个聚合的对象后置处理器，如名字一样，他可以将个后置处理器放在一起调用。
    private static final class CompositeObjectPostProcessor implements ObjectPostProcessor<Object> {
        private List<ObjectPostProcessor<?>> postProcessors;

        private CompositeObjectPostProcessor() {
            this.postProcessors = new ArrayList();
        }
		// 将已经添加起来的后置处理器，分别调用。
        public Object postProcess(Object object) {
            Iterator var2 = this.postProcessors.iterator();

            while(true) {
                ObjectPostProcessor opp;
                Class oppType;
                do {
                    if (!var2.hasNext()) {
                        return object;
                    }

                    opp = (ObjectPostProcessor)var2.next();
                    Class<?> oppClass = opp.getClass();
                    oppType = GenericTypeResolver.resolveTypeArgument(oppClass, ObjectPostProcessor.class);
                } while(oppType != null && !oppType.isAssignableFrom(object.getClass()));

                object = opp.postProcess(object);
            }
        }

        private boolean addObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
            boolean result = this.postProcessors.add(objectPostProcessor);
            this.postProcessors.sort(AnnotationAwareOrderComparator.INSTANCE);
            return result;
        }
    }
}
```

> CompositeObjectPostProcessor()

首先一开始声明了一个 CompositeObjectPostProcessor 实例，CompositeObjectPostProcessor 是 ObjectPostProcessor 的一个实现，ObjectPostProcessor 本身是一个后置处理器，该后置处 理器默认有两个实现，AutowireBeanFactoryObjectPostProcessor 和  CompositeObjectPostProcessor。其中 AutowireBeanFactoryObjectPostProcessor 主要是利用 了 AutowireCapableBeanFactory 对 Bean 进行手动注册，因为在 Spring Security 中，很多对象 都是手动 new 出来的，这些 new 出来的对象和容器没有任何关系，利用 AutowireCapableBeanFactory 可以将这些手动 new 出来的对象注入到容器中，而 AutowireBeanFactoryObjectPostProcessor 的主要作用就是完成这件事； CompositeObjectPostProcessor 则是一个复合的对象处理器，里边维护了一个 List 集合，这个 List 集合中，大部分情况下只存储一条数据，那就是  AutowireBeanFactoryObjectPostProcessor，用来完成对象注入到容器的操作，如果用户自己手 动调用了 addObjectPostProcessor 方法，那么 CompositeObjectPostProcessor 集合中维护的 数据就会多出来一条，在 CompositeObjectPostProcessor#postProcess 方法中，会遍历集合中 的所有 ObjectPostProcessor，挨个调用其 postProcess 方法对对象进行后置处理。 

> add()

该方法返回值是一个 securityBuilder，securityBuilder 实际上就是 HttpSecurity，我们在  HttpSecurity 中去配置不同的过滤器时，可以使用 and 方法进行链式配置，就是因为这里定义了 and 方法并返回了 securityBuilder 实例这便是 SecurityConfigurerAdapter 的主要功能，后面大部分的 xxxConfigurer 都是基于此类来实现的 。

##### GlobalAuthenticationConfigurerAdapter

```java
@Order(100)
public abstract class GlobalAuthenticationConfigurerAdapter implements SecurityConfigurer<AuthenticationManager, AuthenticationManagerBuilder> {
    public GlobalAuthenticationConfigurerAdapter() {
    }

    public void init(AuthenticationManagerBuilder auth) throws Exception {
    }

    public void configure(AuthenticationManagerBuilder auth) throws Exception {
    }
}
```

可以看到，SecurityConfigurer 中的泛型，现在明确成了 AuthenticationManager 和 AuthenticationManagerBuilder。所以 GlobalAuthenticationConfigurerAdapter 的实现类将来主要 是和配置 AuthenticationManager 有关。当然也包括默认的用户名密码也是由它的实现类来进行配置的。我们在 Spring Security 中使用的 AuthenticationManager 其实可以分为两种，一种是局部的，另一种 是全局的，这里主要是全局的配置

##### WebSecurityConfigurer

还有一个实现类就是 WebSecurityConfigurer，这个可能有的小伙伴比较陌生，其实他就是我们天天用的 WebSecurityConfigurerAdapter 的父接口。 所以 WebSecurityConfigurer 的作用就很明确了，用户扩展用户自定义的配置 。

![1616505083962](./img/1616505083962.png)

所以，拥有自定义过滤器，通过SecurityBuilder构造过滤器链，以及配置各种拦截路径，就在继承了WebSecurityConfigurerAdapter成为了可能。

---

让我们把目光回到SecurityConfigurer的第一个实现类，SecurityConfigurerAdapter中，我们来看看下面最重要的三个实现类。其它子类也只不过是他们的三类中的衍生。

* UserDetailAwareConfigurer
* AbstractHttpConfigurer
* LdapAuthenticationProviderConfigurer(用的比较少，这里不介绍)

##### UserDetailAwareConfigurer

![1616505470372](./img/1616505470372.png)

**重点**

关于UserDetailService有关的实现类，都于**用户**有关，这个从名字都能知道，主要用途是SpringSecurity将从这些实现类中获取用户信息和权限信息加以验证，说白点就是个**Repository**，我们可以从数据库获得，或者从其他存储了这些信息的地方获得，这是完全可以自定义的。

![1616505701816](./img/1616505701816.png)

##### UserDetailsAwareConfigurer

```java
public abstract class UserDetailsAwareConfigurer<B extends ProviderManagerBuilder<B>, U extends UserDetailsService> extends SecurityConfigurerAdapter<AuthenticationManager, B> {
    public UserDetailsAwareConfigurer() {
    }
	// 获得一个 UserDetailService的实现
    public abstract U getUserDetailsService();
}
```

从这里开始，预示着用户服务将会与ProviderManager、AuthenticationManager这些权限类有关联，这也不奇怪用户肯定要校验什么的。通过定义我们可以看到泛型U必须是UserDetailsService接口的实现，也就是 getUserDetailsService()方法返回的肯定是UserDetailsService接口的实现，还有通过泛型B及继承 SecurityConfigurerAdapter来看会构建一个AuthenticationManager对象 。

##### AbstractDaoAuthencationConfigurer

```java
public abstract class AbstractDaoAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, C extends AbstractDaoAuthenticationConfigurer<B, C, U>, U extends UserDetailsService> extends UserDetailsAwareConfigurer<B, U> {
    // 权限验证类
    private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    private final U userDetailsService;
	// 将实现类
    AbstractDaoAuthenticationConfigurer(U userDetailsService) {
        this.userDetailsService = userDetailsService;
        this.provider.setUserDetailsService(userDetailsService);
        if (userDetailsService instanceof UserDetailsPasswordService) {
            this.provider.setUserDetailsPasswordService((UserDetailsPasswordService)userDetailsService);
        }

    }
	// 添加到ioc容器中
    public C withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
        this.addObjectPostProcessor(objectPostProcessor);
        return this;
    }
	// 密码加密工具
    public C passwordEncoder(PasswordEncoder passwordEncoder) {
        this.provider.setPasswordEncoder(passwordEncoder);
        return this;
    }
	// 密码服务
    public C userDetailsPasswordManager(UserDetailsPasswordService passwordManager) {
        this.provider.setUserDetailsPasswordService(passwordManager);
        return this;
    }
	//将DaoAuthenticationProvider 添加到IOC容器，且设置进 SecurityBuilder的实现中。
    public void configure(B builder) throws Exception {
        this.provider = (DaoAuthenticationProvider)this.postProcess(this.provider);
        builder.authenticationProvider(this.provider);
    }
	// 返回实现类
    public U getUserDetailsService() {
        return this.userDetailsService;
    }
}
```

##### UserDetailServiceConfigurer

这个类就比较简单，扩展了AbstractDaoAuthenticationConfigurer中的configure方法，在 configure 方法执行之前加入了 initUserDetailsService 方法，以方便开发展按照自己的方式去初始化 UserDetailsService。不过这里的 initUserDetailsService 方法是空方法 。

```java
public class UserDetailsServiceConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsServiceConfigurer<B, C, U>, U extends UserDetailsService> extends AbstractDaoAuthenticationConfigurer<B, C, U> {
    public UserDetailsServiceConfigurer(U userDetailsService) {
        super(userDetailsService);
    }

    public void configure(B builder) throws Exception {
        this.initUserDetailsService();
        super.configure(builder);
    }
	// 给子类开放了一个新的方法，用于重写。
    protected void initUserDetailsService() throws Exception {
    }
}
```

##### DaoAuthenticationConfigurer

```java
public class DaoAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, U extends UserDetailsService> extends AbstractDaoAuthenticationConfigurer<B, DaoAuthenticationConfigurer<B, U>, U> {
    public DaoAuthenticationConfigurer(U userDetailsService) {
        super(userDetailsService);
    }
}
```

这个类也没干什么，就是细化了`AbstractDaoAuthenticationConfigurer<B, DaoAuthenticationConfigurer<B, U>, U>`。

##### UserDetailsManagerConfigurer

```java
public class UserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>, C extends UserDetailsManagerConfigurer<B, C>> extends UserDetailsServiceConfigurer<B, C, UserDetailsManager> {
    private final List<UserDetailsManagerConfigurer<B, C>.UserDetailsBuilder> userBuilders = new ArrayList();
    private final List<UserDetails> users = new ArrayList();

    protected UserDetailsManagerConfigurer(UserDetailsManager userDetailsManager) {
        super(userDetailsManager);
    }
	
    protected void initUserDetailsService() throws Exception {
        Iterator var1 = this.userBuilders.iterator();

        while(var1.hasNext()) {
            UserDetailsManagerConfigurer<B, C>.UserDetailsBuilder userBuilder = (UserDetailsManagerConfigurer.UserDetailsBuilder)var1.next();
            ((UserDetailsManager)this.getUserDetailsService()).createUser(userBuilder.build());
        }

        var1 = this.users.iterator();

        while(var1.hasNext()) {
            UserDetails userDetails = (UserDetails)var1.next();
            ((UserDetailsManager)this.getUserDetailsService()).createUser(userDetails);
        }

    }
	// 用来添加用户，将用户管理起来，方便
    public final C withUser(UserDetails userDetails) {
        this.users.add(userDetails);
        return this;
    }
	// 利用对象构造器，创建一个对象添加到list中
    public final C withUser(UserBuilder userBuilder) {
        this.users.add(userBuilder.build());
        return this;
    }
	// 创建一个对象构建对象，并将利用构造器创建一个指定名字的对象，最后添加进维护的对象建造器列表里
    public final UserDetailsManagerConfigurer<B, C>.UserDetailsBuilder withUser(String username) {
        UserDetailsManagerConfigurer<B, C>.UserDetailsBuilder userBuilder = new UserDetailsManagerConfigurer.UserDetailsBuilder(this);
        userBuilder.username(username);
        this.userBuilders.add(userBuilder);
        return userBuilder;
    }
	// 自定义了一个用户建造对象
    public final class UserDetailsBuilder {
        private UserBuilder user;
        private final C builder;

        private UserDetailsBuilder(C builder) {
            this.builder = builder;
        }

        public C and() {
            return this.builder;
        }

        // ...

        UserDetails build() {
            return this.user.build();
        }
    }
}
```

UserDetailsManagerConfigurer 中实现了 UserDetailsServiceConfigurer 中定义的  initUserDetailsService 方法，具体的实现逻辑就是将 UserDetailsBuilder 所构建出来的 UserDetails 以及提前准备好的 UserDetails 中的用户存储到 UserDetailsService 中。 该类同时添加了 withUser 方法用来添加用户，同时还增加了一个 UserDetailsBuilder 用来构建用户。

##### JdbcUserDetailsManagerConfigurer

JdbcUserDetailsManagerConfigurer 在父类的基础上补充了 DataSource 对象，同时还提供了相应的数据库查询方法 。

```java
public class JdbcUserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>> extends UserDetailsManagerConfigurer<B, JdbcUserDetailsManagerConfigurer<B>> {
    // 数据源
    private DataSource dataSource;
    private List<Resource> initScripts;

    public JdbcUserDetailsManagerConfigurer(JdbcUserDetailsManager manager) {
        super(manager);
        this.initScripts = new ArrayList();
    }

    public JdbcUserDetailsManagerConfigurer() {
        this(new JdbcUserDetailsManager());
    }
	// 数据源的注入
    public JdbcUserDetailsManagerConfigurer<B> dataSource(DataSource dataSource) {
        this.dataSource = dataSource;
        this.getUserDetailsService().setDataSource(dataSource);
        return this;
    }

    public JdbcUserDetailsManagerConfigurer<B> usersByUsernameQuery(String query) {
        this.getUserDetailsService().setUsersByUsernameQuery(query);
        return this;
    }

    public JdbcUserDetailsManagerConfigurer<B> authoritiesByUsernameQuery(String query) {
        this.getUserDetailsService().setAuthoritiesByUsernameQuery(query);
        return this;
    }
 	// ....   
}
```

##### InMemoryUserDetailsManagerConfigurer

```java
public class InMemoryUserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>> extends UserDetailsManagerConfigurer<B, InMemoryUserDetailsManagerConfigurer<B>> {
    public InMemoryUserDetailsManagerConfigurer() {
        // 也就是意味着他会传入 UserDetailsManagerConfigurer，可是这个UserDetailManager又是什么呢
        super(new InMemoryUserDetailsManager(new ArrayList()));
    }
}

// UserDetailsManagerConfigurer.java
protected UserDetailsManagerConfigurer(UserDetailsManager userDetailsManager) {
        super(userDetailsManager);
}
```

其实UserDetailManager就是定义了一些关于User用户的操作接口。

```java
public interface UserDetailsManager extends UserDetailsService {
    void createUser(UserDetails var1);

    void updateUser(UserDetails var1);

    void deleteUser(String var1);

    void changePassword(String var1, String var2);

    boolean userExists(String var1);
}
```

![1616507441936](./img/1616507441936.png)

#### 对 SecurityConigurer的总结

我们可以发现，SecurityConfigurer的下方的子类有三个大类。

![1616508012496](./img/1616508012496.png)

一类是`AbstractHttpConfigurer`，他们最后将会在SecurityBuilder的帮助下，组成了一个个过滤器，并添加到FilterChain中，也就是过滤器链。然后后置处理器将会把他们添加到IOC容器中。

第二类是`UserDetailAwareConfigurer`这一大类主要用途是将权限认证也就是ProviderManager，和用户操作相关的东西放在了一起。

第三类，还没研究，这哪是不用管。  

##### 深入理解 HttpSecurity 

HttpSecurity的最高级抽象，就是SecurityBuilder，他也是SpringSecurity的核心组成部分。

![1616589685138](./img/1616589685138.png)

##### SecurityBuilder

```java
public interface SecurityBuilder<O> {
    O build() throws Exception;
}
```

通过接口的源码我们可以看到它的作用其实就是根据传递的泛型构建对应的对象返回。

```java
public final class HttpSecurity extends AbstractConfiguredSecurityBuilder<DefaultSecurityFilterChain, HttpSecurity> implements SecurityBuilder<DefaultSecurityFilterChain>, HttpSecurityBuilder<HttpSecurity> {
```

集合HttpSecurity的泛型具体，可知道他会创建出`DefaultSecurityFilterChain`，这就是我们熟悉的过滤器链，所以HttpSecurity的主要用途就是为了构建过滤器链。

##### AbstractSecurityBuilder

```java
public abstract class AbstractSecurityBuilder<O> implements SecurityBuilder<O> {
    private AtomicBoolean building = new AtomicBoolean();
    private O object;

    public AbstractSecurityBuilder() {
    }

    public final O build() throws Exception {
        if (this.building.compareAndSet(false, true)) {
            this.object = this.doBuild();
            return this.object;
        } else {
            throw new AlreadyBuiltException("This object has already been built");
        }
    }

    public final O getObject() {
        if (!this.building.get()) {
            throw new IllegalStateException("This object has not been built");
        } else {
            return this.object;
        }
    }

    protected abstract O doBuild() throws Exception;
}
```

我们可以看到，build方法其实在AbstractSecurityBuilder中就是做了一个是否已经初始化过的判断，保证只初始化一次。

而后面却调用了doBuild方法，我们来看看他下面的子类是如何实现的。

##### AbstractConfiguredSecurityBuilder

```java
protected final O doBuild() throws Exception {
    // 模版模式的体现
        synchronized(this.configurers) {
            // 正在初始化
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.INITIALIZING;
            // 初始化之前的调用
            this.beforeInit();
            // 初始化
            this.init();
            // 配置中
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.CONFIGURING;
            // 配置前的调用
            this.beforeConfigure();
            // 配置
            this.configure();
            // 构建创建中
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILDING;
            // 获取构建的对象
            O result = this.performBuild();
            // 已经构建
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILT;
            return result;
        }
}
```

performBuild()【HttpSecurity中实现】方法的代码如下

![1616590519667](./img/1616590519667.png)

HttpSecurity的代码实现

```java
 protected DefaultSecurityFilterChain performBuild() {
     // 这里对过滤器链进行了排序
        this.filters.sort(this.comparator);
     // 对已经创建好的过滤器链和匹配路径对象封装进了DefaultSecurityFilterChain中
        return new DefaultSecurityFilterChain(this.requestMatcher, this.filters);
    }
```

好了SecurityBuilder的接口的功能我们就介绍清楚了，就是用来构建DefaultSecurityFilterChain的。

##### DefaultSecurityFilterChain

DefaultSecurityFilterChain实现了SecurityFilterChain接口，该接口的定义如下。

```java
public interface SecurityFilterChain {
    // 匹配请求
    boolean matches(HttpServletRequest var1);
	// 获取过滤器链中所有的过滤器
    List<Filter> getFilters();
}
```

SecurityFilterChain 其实就是我们平时所说的 Spring Security 中的过滤器链，它里边定义了两个 方法，一个是 matches 方法用来匹配请求，另外一个 getFilters 方法返回一个 List 集合，集合中放着 Filter 对象，当一个请求到来时，用 matches 方法去比较请求是否和当前链吻合，如果吻合，就返回 getFilters 方法中的过滤器，那么当前请求会逐个经过 List 集合中的过滤器 。

DefaultSecurityFilterChain是SecurityFilterChain 的唯一实现，内容就是对SecurityFilterChain 中 的方法的实现。

```java
public final class DefaultSecurityFilterChain implements SecurityFilterChain {
    private static final Log logger = LogFactory.getLog(DefaultSecurityFilterChain.class);
    private final RequestMatcher requestMatcher;
    private final List<Filter> filters;

    public DefaultSecurityFilterChain(RequestMatcher requestMatcher, Filter... filters) {
        this(requestMatcher, Arrays.asList(filters));
    }

    public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
        logger.info(LogMessage.format("Will secure %s with %s", requestMatcher, filters));
        this.requestMatcher = requestMatcher;
        this.filters = new ArrayList(filters);
    }

    public RequestMatcher getRequestMatcher() {
        return this.requestMatcher;
    }

    public List<Filter> getFilters() {
        return this.filters;
    }

    public boolean matches(HttpServletRequest request) {
        return this.requestMatcher.matches(request);
    }

    public String toString() {
        return this.getClass().getSimpleName() + " [RequestMatcher=" + this.requestMatcher + ", Filters=" + this.filters + "]";
    }
}
```

##### HttpSecurityBuilder

HttpSecurityBuilder 看名字就是用来构建 HttpSecurity 的。不过它也只是一个接口，具体的实现 在 HttpSecurity 中，接口定义如下。

```java
public interface HttpSecurityBuilder<H extends HttpSecurityBuilder<H>> extends SecurityBuilder<DefaultSecurityFilterChain> {
    <C extends SecurityConfigurer<DefaultSecurityFilterChain, H>> C getConfigurer(Class<C> var1);

    <C extends SecurityConfigurer<DefaultSecurityFilterChain, H>> C removeConfigurer(Class<C> var1);

    <C> void setSharedObject(Class<C> var1, C var2);

    <C> C getSharedObject(Class<C> var1);

    H authenticationProvider(AuthenticationProvider var1);

    H userDetailsService(UserDetailsService var1) throws Exception;

    H addFilterAfter(Filter var1, Class<? extends Filter> var2);

    H addFilterBefore(Filter var1, Class<? extends Filter> var2);

    H addFilter(Filter var1);
}
```

方法的说明

| 方法名称               | 说明                                                         |
| ---------------------- | ------------------------------------------------------------ |
| getConfigurer          | 获取一个配置对象。Spring Security 过滤器链中的所有过滤器对象都 是由 xxxConfigure 来进行配置的，这里就是获取这个 xxxConfigure对象 |
| removeConfigurer       | 移除一个配置对象                                             |
| setSharedObject        | 配置由多个 SecurityConfigurer 共享的对象。                   |
| getSharedObject        | 获取由多个 SecurityConfigurer 共享的对象                     |
| authenticationProvider | 表示配置验证器                                               |
| userDetailsService     | 配置数据源接口                                               |
| addFilterAfter         | 在某一个过滤器之前添加过滤器                                 |
| addFilterBefore        | 在某一个过滤器之后添加过滤器                                 |
| addFilter              | 添加一个过滤器，该过滤器必须是现有过滤器链中某一个过滤器或者 |

这些接口在HttpSecurity中都有实现。

AbstractSecurityBuilder是SecurityBuilder的唯一实现类，他里面只有一个build方法，此外还开放了一个doBuild方法，给子类用。

AbstractConfigurerSecurityBuilder是AbstractSecurityBuilder的子类。此外AbstractConfiguredSecurityBuilder虽然也是个抽象类，但也开始有一些SecurityBuilder的一些实现。

首先 AbstractConfiguredSecurityBuilder 中定义了一个枚举类，将整个构建过程分为 5 种状态，也可 以理解为构建过程生命周期的五个阶段，如下： 

```java
private static enum BuildState {
        // 未构建
    	UNBUILT(0),
        // 初始化中
    	INITIALIZING(1),
        // 配置中
    	CONFIGURING(2),
    	// 构建中
        BUILDING(3),
    	// 构建完成
        BUILT(4);

        private final int order;

        private BuildState(int order) {
            this.order = order;
        }

        public boolean isInitializing() {
            return INITIALIZING.order == this.order;
        }

        public boolean isConfigured() {
            return this.order >= CONFIGURING.order;
        }
    }
```

同时我们来看他的成员变量就知道这个类做了什么事情。

```java
	//用于存储SecurityConfigurer的信息 class类和对应实体的映射关系。
    private final LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>> configurers;
	// 在 builder为initing阶段时候添加进来的configuer
    private final List<SecurityConfigurer<O, B>> configurersAddedInInitializing;
    // 存储通过addShared的Configurer对象
	private final Map<Class<?>, Object> sharedObjects;
    private final boolean allowConfigurersOfSameType;
	// 改建造者现在的状态
    private AbstractConfiguredSecurityBuilder.BuildState buildState;
	// 后置处理器，用于托管对象给IOC容器。    
	private ObjectPostProcessor<Object> objectPostProcessor;
```

也就意味着，AbstractConfigurerSecurityBuilder是开始将SecurityConfiguerer和FilterChain放在一起操作的类，通过收集SecurityConfigurer信息，从中构造出FilterChain，最后生成匹配的url对象一起过滤器链封装成一个DefaultSecurityFilterChain对象返回。

我们来看两个方法。

> add 方法

```java
private <C extends SecurityConfigurer<O, B>> void add(C configurer) {
    Assert.notNull(configurer, "configurer cannot be null");
    Class<? extends SecurityConfigurer<O, B>> clazz = configurer.getClass();
    synchronized(this.configurers) {
        //当前是否是已经配置过的阶段
        if (this.buildState.isConfigured()) {
            throw new IllegalStateException("Cannot apply " + configurer + " to already built object");
        } else {
            List<SecurityConfigurer<O, B>> configs = null;
            //是否允许相同类型地Configurer
            if (this.allowConfigurersOfSameType) {
                configs = (List)this.configurers.get(clazz);
            }

            List<SecurityConfigurer<O, B>> configs = configs != null ? configs : new ArrayList(1);
            ((List)configs).add(configurer);
            //class和对象的对象的映射关系
            this.configurers.put(clazz, configs);
            if (this.buildState.isInitializing()) {
                this.configurersAddedInInitializing.add(configurer);
            }

        }
    }
}

// 获取所有的Configurer
 public <C extends SecurityConfigurer<O, B>> List<C> getConfigurers(Class<C> clazz) {
        List<C> configs = (List)this.configurers.get(clazz);
        return configs == null ? new ArrayList() : new ArrayList(configs);
    }
```

add 方法，这相当于是在收集所有的配置类。将所有的 xxxConfigure 收集起来存储到 configurers  中，将来再统一初始化并配置，configurers 本身是一个 LinkedHashMap ，key 是配置类的 class， value 是一个集合，集合里边放着 xxxConfigure 配置类。当需要对这些配置类进行集中配置的时候， 会通过 getConfigurers 方法获取配置类，这个获取过程就是把 LinkedHashMap 中的 value 拿出来， 放到一个集合中返回 。

> doBuild 方法

```java
protected final O doBuild() throws Exception {
        synchronized(this.configurers) {
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.INITIALIZING;
            this.beforeInit();
            this.init();
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.CONFIGURING;
            this.beforeConfigure();
            this.configure();
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILDING;
            O result = this.performBuild();
            this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILT;
            return result;
        }
    }
// 依次调用收集到的Configurer类，迭代调用
private void init() throws Exception {
        Collection<SecurityConfigurer<O, B>> configurers = this.getConfigurers();
        Iterator var2 = configurers.iterator();

        SecurityConfigurer configurer;
        while(var2.hasNext()) {
            configurer = (SecurityConfigurer)var2.next();
            configurer.init(this);
        }

        var2 = this.configurersAddedInInitializing.iterator();

        while(var2.hasNext()) {
            configurer = (SecurityConfigurer)var2.next();
            configurer.init(this);
        }

    }
	// 依次调用收集到的Configurer类，迭代调用
    private void configure() throws Exception {
        Collection<SecurityConfigurer<O, B>> configurers = this.getConfigurers();
        Iterator var2 = configurers.iterator();

        while(var2.hasNext()) {
            SecurityConfigurer<O, B> configurer = (SecurityConfigurer)var2.next();
            configurer.configure(this);
        }

    }
```

在 AbstractSecurityBuilder 类中，过滤器的构建被转移到 doBuild 方法上面了，不过在  AbstractSecurityBuilder 中只是定义了抽象的 doBuild 方法，具体的实现在  AbstractConfiguredSecurityBuilder doBuild 方法就是一边更新状态，进行进行初始化。

其中调用方法的说明

| 方法              | 说明                                                         |
| ----------------- | ------------------------------------------------------------ |
| beforeInit()      | 是一个预留方法，没有任何实现                                 |
| init()            | 就是找到所有的 xxxConfigure，挨个调用其 init 方法进行初始化  |
| beforeConfigure() | 是一个预留方法，没有任何实现                                 |
| configure()       | 就是找到所有的 xxxConfigure，挨个调用其 configure 方法进行配置。 |
| performBuild()    | 是真正的过滤器链构建方法，但是在 AbstractConfiguredSecurityBuilder 中 performBuild 方法只是一个抽象方法，具体的实现在 HttpSecurity 中 |

HttpSecurity的所有的父类我们都了解后就可以具体来看下HttpSecurity的内容了。

##### HttpSecurity

![1616592762371](./img/1616592762371.png)

HttpSecurity 中有大量类似的方法，过滤器链中的过滤器就是这样一个一个配置的。我们就不一一介绍 

了。 每个配置方法的结尾都会来一句 getOrApply，这个是干嘛的？我们来看下。

![1616592848362](./img/1616592848362.png)



```java
// HttpSecurity.java 
private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(C configurer) throws Exception {
        C existingConfig = (SecurityConfigurerAdapter)this.getConfigurer(configurer.getClass());
        return existingConfig != null ? existingConfig : this.apply(configurer);
    }

//AbstractConfiguredSecurityBuilder.java
public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer) throws Exception {
        configurer.addObjectPostProcessor(this.objectPostProcessor);
        configurer.setBuilder(this);
        this.add(configurer);
        return configurer;
}
// 将配置类收集起来。
private <C extends SecurityConfigurer<O, B>> void add(C configurer) {
        Assert.notNull(configurer, "configurer cannot be null");
        Class<? extends SecurityConfigurer<O, B>> clazz = configurer.getClass();
        synchronized(this.configurers) {
            if (this.buildState.isConfigured()) {
                throw new IllegalStateException("Cannot apply " + configurer + " to already built object");
            } else {
                List<SecurityConfigurer<O, B>> configs = null;
                if (this.allowConfigurersOfSameType) {
                    configs = (List)this.configurers.get(clazz);
                }

                List<SecurityConfigurer<O, B>> configs = configs != null ? configs : new ArrayList(1);
                ((List)configs).add(configurer);
                this.configurers.put(clazz, configs);
                if (this.buildState.isInitializing()) {
                    this.configurersAddedInInitializing.add(configurer);
                }

            }
        }
    }
```

getConfigurer 方法是在它的父类 AbstractConfiguredSecurityBuilder 中定义的，目的就是去查看当前 这个 xxxConfigurer 是否已经配置过了。 如果当前 xxxConfigurer 已经配置过了，则直接返回，否则调用 apply 方法，这个 apply 方法最终会调 用到 AbstractConfiguredSecurityBuilder#add 方法，将当前配置 configurer 收集起来。

> addFilter 方法

```java
public HttpSecurity addFilter(Filter filter) {
    Class<? extends Filter> filterClass = filter.getClass();
    // 是否注册过
    if (!this.comparator.isRegistered(filterClass)) {
        throw new IllegalArgumentException("The Filter class " + filterClass.getName() + " does not have a registered order and cannot be added without a specified order. Consider using addFilterBefore or addFilterAfter instead.");
    } else {
        //很简单粗暴，就是添加到过滤器链中
        this.filters.add(filter);
        return this;
    }
}
```

##### 总结HttpSecurity

其实HttpSecurity的真正目的就是为了构建DefaultSecurityFilterChain，也就是过滤器链。那么为了能够创建出这个链，我们需要收集一些Configurer，也就是SecurityConfigurer下的AbstractHttpConfigurer锁衍生出来的实现类，他们用于创建不同的过滤器链，在由于SecurityBuilder也定义了一套收集Configurer，调用他们的init和configre的方法，使得他们能够依次被初始化成功，最后利用传入的SecurityBuilder，也就是HttpSecuirty将构造好的Filter添加到链表中，最后和配置好的请求，封装成链表返回。



##### 默认的登录流程

通过之前的流程我们知道，第一次的请求web项目的时候会判断你这个请求是否是不需要授权的请求，如果是不需要授权，就会放行，否则就会进行重定向到权限认证页面。在后台生成了页面返回到浏览器后，我们需要输入账号密码，这之后的请求又是什么样的流程呢。

首先我们确定的是，这个处理也是在过滤器中的处理的，那么我们更加前面的知道，一个过滤器对应了一个`Configurer`，那么我们来到这里的`FromLoginConfigurer`

![image-20210329134817863](./img/image-20210329134817863.png)

这里很明显，他创建一个`UsernamePasswordAuthenticationFilter`，也符合我们一个`Configurer`对应一个过滤器的结论。

确实这个过滤器也出现在我们的`FilterChainProxy`中。

![image-20210329135747440](./img/image-20210329135747440.png)

看看configurer对应的init方法干了什么。

![image-20210329135842875](./img/image-20210329135842875.png)

```java
private void initDefaultLoginFilter(H http) { DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http .getSharedObject(DefaultLoginPageGeneratingFilter.class); 
if (loginPageGeneratingFilter != null && !isCustomLoginPage()) { 
// 都是一些配置的设置
loginPageGeneratingFilter.setFormLoginEnabled(true); loginPageGeneratingFilter.setUsernameParameter(getUsernameParameter()); loginPageGeneratingFilter.setPasswordParameter(getPasswordParameter()); 
 // 设置认证页面的地址 
loginPageGeneratingFilter.setLoginPageUrl(getLoginPage()); loginPageGeneratingFilter.setFailureUrl(getFailureUrl()); 
// 设置默认页面提交表单的地址 
loginPageGeneratingFilter.setAuthenticationUrl(getLoginProcessingUrl()); 
} 
}
```

对应的父类的实现为

![image-20210329140536206](./img/image-20210329140536206.png)

这里有设置默认的实现登录接口路径`/login`。

##### 默认的认证流程

当我们提交登陆表单后该请求会被 `UsernamePasswordAuthenticationFilter` 过滤器处理。`doFilter`方法在`UsernamePasswordAuthenticationFilter` 的**父类**中首先如果不是需要认证的请求就直接放过了，如果是需要认证的方法就会调用子类中的`attemptAuthentication`方法来处理。

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException { 
    HttpServletRequest request = (HttpServletRequest)req; 
    HttpServletResponse response = (HttpServletResponse)res; 
    // 如果不是需要认证的请求 直接放过 
    if (!this.requiresAuthentication(request, response)) { 
        chain.doFilter(request, response); 
    } else 
    { 	if (this.logger.isDebugEnabled()) { 
        this.logger.debug("Request is to process authentication"); 
    }
     Authentication authResult; 
     try {
         // 调用子类认证的方法 进入
         attemptAuthenticatio 方法 authResult = 
             this.attemptAuthentication(request, response); 
         if (authResult == null) { 
             return; 
         }// session的处理策略 
         this.sessionStrategy.onAuthentication(authResult, request, response);
     } catch (InternalAuthenticationServiceException var8) { 
         this.logger.error("An internal error occurred while trying to authenticate the user.", var8); 
         // 验证失败的处理方法
         this.unsuccessfulAuthentication(request, response, var8); 
         return; 
     } catch (AuthenticationException var9) { 
         this.unsuccessfulAuthentication(request, response, var9); 
         return; 
     }
     //验证成功前的操作
     if (this.continueChainBeforeSuccessfulAuthentication) { 
         chain.doFilter(request, response); 
     }
     //都成功后的处理
     this.successfulAuthentication(request, response, chain, authResult); 
    } 
}
```

进入`UsernamePasswordAuthenticationFilter`中的`attemptAuthentication`方法

```java
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException { 
    // 表单提交的方式必须是POST方式 
    if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod()); 
    } else 
    { 
        // 获取表单提交的账号密码 
        String username = this.obtainUsername(request); 
        String password = this.obtainPassword(request); 
        if (username == null) { 
            username = ""; 
        }
        if (password == null) { 
            password = ""; 
        }
        username = username.trim(); 
        // 表单提交的账号密码被封装为 Token对象 
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password); 
        // 将当前Request和Token关联起来 
        this.setDetails(request, authRequest); 
        // 实现认证的过程 进入这里，这里进入的其实是ProviderManager
        return this.getAuthenticationManager().authenticate(authRequest); 
    } 
}
```

authenticate认证的方法我们需要进入到`ProviderManager`中获取对应的验证方式，`ProviderManager`是`AuthenticationManager`的实现类，主要的用途是处理认证的请求。

![image-20210329142940568](./img/image-20210329142940568.png)

```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException { 
    Class<? extends Authentication> toTest = authentication.getClass(); 		      		AuthenticationException lastException = null; 
    AuthenticationException parentException = null; 
    Authentication result = null; 
    Authentication parentResult = null; 
    boolean debug = logger.isDebugEnabled(); 
    // 获取各种认证方式 QQ 微信 数据库 
    Iterator var8 = this.getProviders().iterator(); 
    while(var8.hasNext()) { 
        //迭代，获得校验提供者
        AuthenticationProvider provider = (AuthenticationProvider)var8.next(); 
        //是否支持这个校验
        if (provider.supports(toTest)) { 
            if (debug) { 
                logger.debug("Authentication attempt using " + provider.getClass().getName()); 
            }try {
                // 认证的关键代码 
                result = provider.authenticate(authentication);
				if (result != null) { 
                    this.copyDetails(authentication, result); 
                    break; 
                } 
            } catch (AccountStatusException var13) { 
                this.prepareException(var13, authentication); 
                throw var13; 
            } catch (InternalAuthenticationServiceException var14) { 		                             this.prepareException(var14, authentication); 
                throw var14; 
            } catch (AuthenticationException var15) { 
                lastException = var15; 
            } 
        } 
    }
    if (result == null && this.parent != null) { 
        try {
            // 父认证器 再认证一次 
            result = parentResult = this.parent.authenticate(authentication); 
        } catch (ProviderNotFoundException var11) {
        } catch (AuthenticationException var12) { 
            parentException = var12; lastException = var12; 
        } 
    }
    if (result != null) { 
        if (this.eraseCredentialsAfterAuthentication && result instanceof CredentialsContainer) 
        { 
            ((CredentialsContainer)result).eraseCredentials(); }
        if (parentResult == null) { 	                this.eventPublisher.publishAuthenticationSuccess(result); 
        }return result; 
    } 
    else { 
        if (lastException == null) { 
            lastException = new ProviderNotFoundException(this.messages.getMessage("ProviderManager.providerNotF ound", new Object[]{toTest.getName()}, "No AuthenticationProvider found for {0}")); 
        }if (parentException == null) { this.prepareException((AuthenticationException)lastException, authentication); 
        }throw lastException;
    } 
}
```

进入`provider.authenticate(authentication);`方法中 `AbstractUserDetailsAuthenticationProvider`具体实现。

![image-20210329144027556](./img/image-20210329144027556.png)

```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException { 
    Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, () -> { 
        return this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports ", "Only UsernamePasswordAuthenticationToken is supported"); 
    }); 
    // 获取表单提交的账号 
    String username = authentication.getPrincipal() == null ? "NONE_PROVIDED" : authentication.getName(); boolean cacheWasUsed = true; 
    // 从缓存中认证账号是否存在 
    UserDetails user = this.userCache.getUserFromCache(username); 
    if (user == null) { 
        cacheWasUsed = false; 
     try {
         // 缓存中不存在要验证的账号 直接验证 
         user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication); 
     } catch (UsernameNotFoundException var6) { 
         this.logger.debug("User '" + username + "' not found"); if (this.hideUserNotFoundExceptions) 
         { 
             throw new BadCredentialsException(
                 this.messages.getMessage("AbstractUserDetailsAuthenticat ionProvider.badCredentials", "Bad credentials")
             ); 
         }throw var6;
     }
        Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract"); 
    }try 
    {
     // 验证前，先判断判断这个用户是不是session超时，或者是锁定的状态，
     this.preAuthenticationChecks.check(user); 
      // 密码是否正确
     this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication); 
    } catch (AuthenticationException var7) 
    { 
        if (!cacheWasUsed) 
        { 	
            throw var7; 
    	}

		cacheWasUsed = false; 
        // 由于上面没有缓存，所以这个会去查询，通过用户账号
        user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication); 
        // 和上面一样
        this.preAuthenticationChecks.check(user); 
        // 和上面一样
  this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication); }
    this.postAuthenticationChecks.check(user); 
    if (!cacheWasUsed) 
    { 
        //放进缓存
        this.userCache.putUserInCache(user); 
    }
    Object principalToReturn = user; 
    if (this.forcePrincipalAsString) { 
        principalToReturn = user.getUsername(); 
    }
    // 返回验证成功的信息。
    return this.createSuccessAuthentication(principalToReturn, authentication, user); 
}
```

所以这一步，也还是没到验证的步骤，进入`retrieveUser`方法

![image-20210329150515940](./img/image-20210329150515940.png)

```java
protected final UserDetails retrieveUser(
    String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException { 
    this.prepareTimingAttackProtection(); 
    try {
        // 账号验证 
        // 其实一切的验证还是回到了UserDetialService 这个用户数据中心这里。
        UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username); 
        //账号不存在就报错
        if (loadedUser == null) { 
            throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation"); 
        } 
        else 
        { 
            // 存在就直接返回。
            return loadedUser; 
        } 
    } catch (UsernameNotFoundException var4) 
    { 	 
        //用户名不存在也报错
        this.mitigateAgainstTimingAttack(authentication);
		throw var4; 
    } 
    catch (InternalAuthenticationServiceException var5) { 
        throw var5; 
    } catch (Exception var6) { 
        throw new InternalAuthenticationServiceException(var6.getMessage(), var6);
    } 
}
```

我们在这里可以看到，这里最后开始调用UserDetailService接口里的方法，尝试从用户数据中心那里获得用户信息，如果你没有实现自己的UserDetailService话，springsecurity会有一个自己的默认实现，就是InMemoryUserDetailsManager中的实现，有一个默认的用户名和密码。如果你实现了自己的，这个对象就不会被注入。

![image-20210329151220711](./img/image-20210329151220711.png)

我们看看InMemoryUserDetailsManager中的loadUserByUsername的实现

![image-20210329151512687](./img/image-20210329151512687.png)

这里的用户名密码，你可以通过外部的配置的yml文件配置，也有默认的，之前看过了，用户名是user，密码是一串随机生成的uuid。这里就是如他名字一样，直接在内存中校验了。

##### 密码校验

我们通过上面那一步，通过用户名获得了账号信息，接着就要看看密码是否匹配。这是在用户已经查询到的情况下。所以让我们跳出来。接着走完校验流程。

![image-20210329152236915](./img/image-20210329152236915.png)

![image-20210329152513718](./img/image-20210329152513718.png)

接着，我们通过代码调试，发现这个获得的`passwordEncoder`的实现类是`DelegatingPasswordEncoder`

![image-20210329152700304](./img/image-20210329152700304.png)

当然，关于密码的encoder也有很多种实现，例如我们可以在加入密码的时候，在密码的前面设置`{noop}`前缀，代表对密码不进行加密校验。所以也会获得不用加密的密码加密工具。就像是下面这样。

![image-20210329152914615](./img/image-20210329152914615.png)

这其实就是一些映射，也就意味着你可以在你的密码前面加上这些前缀来获得不同的加密工具，来对你的密码进行校验，不过这个你必须保证，你注册账号所加密的密码，和这里解密的密码工具是一致的才行。

也就意味着你可以这样写密码。

```
{noop}123    NoOpPasswrodEncoder
{SHA-1}123	 MessageDigestPasswordEncoder
....
```

![image-20210329153125602](./img/image-20210329153125602.png)

这里也就是一个简单的密码判断。判断字符是否相同。

![image-20210329153153082](./img/image-20210329153153082.png)

##### 关于登录和校验流程的总结

在重定向登录页面，我们输入用户名密码后，会被`UserPasswordAuthenticationFilter`过滤器拦截下来。`UserPasswordAuthenticationFilter`是从`LoginFormConfigurer`中创建出来的。接着在父类`AbstractAuthencationFilterConfigurer`指定了登录路径为`/login`路径，作为拦截匹配对象。

接着，进入`UserPasswordAuthenticationFilter`的`doFilter`方法进行校验，然后一直往下走，我们发现了一个新的类叫做`AuthenticationManager`这个对象中就是个验证管理中心，里面持有了一个`UserDetailService`的引用。主要从里面来获得对象处理，然后封装成Authentication对象返回。然后再后续的步骤中，就是校验取出的用户是否锁定，是否session过期之类的。最后都没问题开始密码校验。

关于密码校验，就是通过不同的前缀来找到不同的密码加密器，也就是`PasswordEncoder`来和取出的密码进行简单的比对。最后全部完成后，会将用户信息存入缓存。放行。



#### 应用篇

关键在于我们如何将`springsecurity`组合到我们的项目中去，除了之前的映入jar的操作，无非就是和`shiro`一样可以需要自己配置权限的来源，和用户的来源之类的，以及记住我等配置。

一开始，我们可以通过修改默认的配置，也就是在`application.properties`里面修改默认的用户名和密码，接着你也可以在新建一个`SpringSecurity`的配置类，里覆盖里面的配置。

```java
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{
	
    /**
    自定义权限认证器，此方法来自于 GlobalAuthenticationConfigurerAdapter 也就是
    SecurityConfigurer的子类，用来构建和认证权限相关的配置
    **/
    @Overriede
    protected void configure(AuthenticationManagerBuildr auth) throws Exception
    {
        //这里我们调用默认的内存权限认证，随便设置几个值
        auth.inMemoryAuthentication().withUser("pop").password("{noop}123")//不加密
            .roles("USER");//随便赋予了一个权限字符
    }
    
    /**
    自定义过滤器连，这个来自于securityBuilder，用来构造自己过滤器链
    */
    protected void configure(HttpSecurity http) throws Exception{
        super.configure(http);//保持原样
    }
    
}
```

##### 自定义用户中心

以上是默认的流程，默认情况下通过`InMemoryUserDetailManager`来实现，而`InMemoryUserDetailsManager`实现了`UserDetailService`接口，那么我们要实现自定义的认证流程也只需要实现`UserDetailService`接口，重写`loadUserByUsername`方法，然后将这个我们自定义的实现，塞进到这个`InMemoryUserDetailManager`即可。

```java
public interface UserService extends UserDetailsService{
    //....
}

@Service
public class UserServiceImpl implements UserService {
    
    /*
     通过用户名查找用户
    */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        
        // 一段从数据库，或者内存中，通过用户名或者UserDetails的代码
        // ....
        // 结束...  UserDetail是Security自己定义的对象实体，按照规范返回即可。
        
        //保存权限的集合，其实就是一串封装起来的代表权限的字符串
        List<SimpleGrantedAuthority> list = new ArrayList<>();
        // 这里也建议从 数据库或者内存中获取权限的代码，然后封装返回
        list.add(new SimpleGantedAuthority("USER"));
        //这里是简单的校验
        if(!"lisi".equals(username))
        {
            return null;
        }
        //将用户名和密码，权限封装起来
        UserDetail user = new User("lisi","{noop}123",list);
        return user;
    }
    
}
```

以上定义好了，也就意味着我们自定义了自己的用户校验规则，接着将他注入到权限管理器中。

```java
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{
	
    @Autowired
    private UserService userService;
    
    /**
    自定义权限认证器，此方法来自于 GlobalAuthenticationConfigurerAdapter 也就是
    SecurityConfigurer的子类，用来构建和认证权限相关的配置
    **/
    @Overriede
    protected void configure(AuthenticationManagerBuildr auth) throws Exception
    {
        //这里我们调用默认的内存权限认证，随便设置几个值
       /* auth.inMemoryAuthentication().withUser("pop").password("{noop}123")//不加密
            .roles("USER");//随便赋予了一个权限字符*/
        auth.userDetailsService(userService);
    }
    
    /**
    自定义过滤器连，这个来自于securityBuilder，用来构造自己过滤器链
    */
    protected void configure(HttpSecurity http) throws Exception{
        super.configure(http);//保持原样
    }
    
}
```

##### 自定义加密处理

之前我们有说过`PasswordEncoder`这个接口，他会根据你传过来密码的前缀来选择不同的加密密码的策略实现，例如`{noop}123`就是使用不加密的加密策略。以下是目前`SpringSecurity`支持的加密策略。

![image-20210329153125602](./img/image-20210329153125602.png)

这里我们用`BcryptPasswordEncoder`来加密。

![image-20210330164628919](./img/image-20210330164628919.png)

这个加密的用处在于，每次都会生成一个随机的salt，同一个明文密码多次编码得到的密文其实是不一样的。

```java
public static void main(String[] args)
{
    BCryptPasswordEncoder bCrypt = new BCryptPasswordEncoder();
    String password = "123456";
    System.out.println(bCrypt.encode(password));
    System.out.println(bCrypt.encode(password));   
    System.out.println(bCrypt.encode(password));   
    System.out.println(bCrypt.encode(password));  
}
```

输出的密文。

![image-20210330165114327](./img/image-20210330165114327.png)

![image-20210330165515796](./img/image-20210330165515796.png)

那么，如果注册用户的话，将这个密码存进去就好了，之后会比对。

![image-20210330165702525](./img/image-20210330165702525.png)

当然，按照源码，如果你没有设置密码加密类，他会根据前缀判断，如果有就会使用设置的。

![image-20210329152914615](./img/image-20210329152914615.png)

```java
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{
	
    @Autowired
    private UserService userService;
    
    /**
    自定义权限认证器，此方法来自于 GlobalAuthenticationConfigurerAdapter 也就是
    SecurityConfigurer的子类，用来构建和认证权限相关的配置
    **/
    @Overriede
    protected void configure(AuthenticationManagerBuildr auth) throws Exception
    {
        //这里我们调用默认的内存权限认证，随便设置几个值
       /* auth.inMemoryAuthentication().withUser("pop").password("{noop}123")//不加密
            .roles("USER");//随便赋予了一个权限字符*/
        auth.userDetailsService(userService).passwordEncoder(new BCryptPasswordEncoder);
    }
    
    /**
    自定义过滤器连，这个来自于securityBuilder，用来构造自己过滤器链
    */
    protected void configure(HttpSecurity http) throws Exception{
        super.configure(http);//保持原样
    }
    
}
```

其实，看到这里，你也可以自己实现他的`PasswordEncoder`的接口，自定义自己的加密工具，也是完全可以的。

##### 用户的认证状态

`SpringSecurity`中的所定义的`User`，含有多种状态，包括是否可用，是否超时，是否冻结，是否锁定等。

![image-20210330170430450](./img/image-20210330170430450.png)

User对象的属性中是定义了各种状态的对应关系。

| 参数                          | 说明         |
| ----------------------------- | ------------ |
| boolean enabled               | 是否可用     |
| boolean accountNonExpired     | 账号是否失效 |
| boolean credentialsNonExpired | 密匙是否失效 |
| boolean accountNonLocked      | 账号是否锁定 |

所以这里就留给我们一定的遐想攻坚，在我们通过自定义的`UserDetailService`的时候，实现`loadUserByUsername`的时候，通过某种我们自己的在数据库字段定义，又或者校验，完整这些参数的初始化，从让`springsecurity`配合我们完成这些校验等。

![image-20210330170916453](./img/image-20210330170916453.png)

实际页面返回的效果。

![image-20210330170953658](./img/image-20210330170953658.png)

##### 自定义认证页面

当然，如果登录页面无法自定义的话，那也是不行的，我们引入`Thymeleaf`来实现，当然这只是一案例而已，如果你不喜欢可以不用`thymeleaf`。

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```

登录页面

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org">
    <head>
        <meta charset="utf-8">
        <title>title</title>
    </head>
    <body>
        <h1>
            登录管理
        </h1>
        <form th:action="@{/login.do}" method="post">
            账号:<input type="text" name="username"><br/>
            密码:<input type="password" name="password"><br/>
            <input type="submit" value="登录"><br/>
        </form>
    </body>
</html>
```

同时，我们需要在SpringSecurity中改掉一些默认的配置。

```java
@Override
protected void configure(HttpSecurity http) throws Exception{
//    super.configure(http); 不再调用父类中的方法，使用默认的过滤器链，而是使用我们自定义的。
    http.authorizeRequests()
        // 对于登录请求，失败请求，放过
        .antMatchers("/login","/failure.html").permitAll()//放过
        .anyRequest().authenticated() // 除此之外的全部请求，都需要验证
        .and()
        .formLogin()//认证表单
        .loginPage("/login")//自定义的认证界面
        .usernameParameter("username")
        .passwordParameter("password")
        .loginProcessingUrl("/login.do")
        // 认证成功的跳转页面，默认是get方式提交，自定义的成功页面后会post方式提叫，在controller中处理需要注意
        .defaultSucessUrl("/home")//成功后跳转
        .failureUrl("/failure") // 失败的跳转
        .permitAll()
        .and()
        .logout()
        .logoutUrl("/logout")
        .invalidateHttpSession(true)//注销会话
        .logoutSuccessUrl("/login")//注销成功后跳转页面
        .permitAll();
}
```

#### CSRF 跨域攻击

##### CSRF介绍

CSRF（Cross-site request forgery）伪站请求伪造，也被称呼为`One Click Attack` 或者 `Session Riding`，通常缩写为CSRF或者XSRF，是对网站的一种恶意利用。

![1617109983543](./img/1617109983543.png)

首先我们知道，我们自己通过输入帐号和密码的方式在成功登陆一个网站后，是可以浏览和使用这个网站的功能的，这是毋庸置疑，对于服务端来说，在我们登陆后，他会将我们的信息加密放入使用set-Cookie的方式，将信息通过浏览器写到我们客户端的cookie中，同时也许服务端也会将一部分信息存储到session中。等到我们再次访问，服务器会从cookie中获取我们的信息来确定是我们本人来访问。

CSRF攻击关键点则是借助**我们的手来完成对我们自己的攻击，让我们不知不觉受到损失**。

![1617110526422](./img/1617110526422.png)

就比如，你在浏览银行网站的时候，这个时候，你又打开了其它的tab页，由于你当前是登陆状态，session和cookie都没有过期的情况下，实际上你对网站的所有请求，网站都会认为是你的正常操作。

这个时候你打开的tab页面弹出了一个你感兴趣的东西，可能是一张图片，你很好奇的点进去，这个时候，图片中也许隐藏了一段含有攻击的代码，这段代码也许是以你的信息想黑客希望的账户转钱的一个请求，这个其实很容易实现，你只需要。

```html
<img scr="感兴趣的图片.png" onClick="attakCode()"/>

<script>
    function attakCode(){
        window.open("www.blank.com/转账给小黑的请求");
    }
</script>
```

当你点击了这个图片后，他会执行一段转账的代码。

```
www.blank.com/转账给小黑的请求
```

由于你此刻确实是登陆的状态，所以对于银行网站来说，这个请求是你点击的，也确实是你自己发送出去的，所以他就会按照请求内容，转账给小黑。

##### 常用的解决方案

> 验证Http Referer 字段

根据HTTP协议，在HTTP头中，有一个字段叫做Referer，他记录了HTTP请求的来源地址。

![1617111178376](./img/1617111178376.png)

也就意味着客户端请求来源，如果是本网站的则响应，否则不响应，但是。

* 对于某些浏览器，比如IE6或FF2，目前已经有一些方法可以篡改Referer的值
* 用户自己可以设置浏览器使其在发送请求时不再提供Referer

> 使用Token解决

token的技术可以说是web有关权限验证的万精油了。由于token必须符合服务器所颁发的这一要求，也就意味着只有符合服务器规则的token才可以被允许通过。也就是防伪标志。

![1617111532969](./img/1617111532969.png)

这个token的值必须是随机的。由于Token的存在，攻击者无法再构造一个带有合法Token的请求实施CSRF攻击。另外使用Token时应注意Token的保密性，尽量将敏感操作由GET改成POST，以form或者AJAX形式提交，避免Token泄露。

##### SpringSecurity 中的处理

我们回到之前的配置类，只需要加上上面这句话。

```java
 .invalidateHttpSession(true)//注销会话
                .logoutSuccessUrl("/login")//注销成功后跳转页面
                .permitAll()
                .and()
                .csrf();
//如果希望禁用
 .invalidateHttpSession(true)//注销会话
                .logoutSuccessUrl("/login")//注销成功后跳转页面
                .permitAll()
                .and()
                .csrf()
     			.disable();
```

![1617111887319](./img/1617111887319.png)

从配置中移除，也就意味着不会再生成这个过滤器了。

首先，我们这里使用的是thymeleaf的，所以当你开启了csrf的时候，他会在你的登录表单里塞入一个`_csrf`的隐藏域，这很好理解，因为模版引擎会先静态资源读取到内存中，再写到response中，这个期间，自然是可以对静态资源**为所欲为**，加一个简单的字段也是不成问题的。

![1617112369502](./img/1617112369502.png)

![1617112174948](./img/1617112174948.png)

如果你把他关掉了`disable`，自然就没有了。因为他会将他从列表中剔除。

![1617112243920](./img/1617112243920.png)

我们再看看页面。

![1617112308268](./img/1617112308268.png)

那么很明显，我们可以从`CsrfFilter`入手。

```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    	//将响应设置到request的属性中
        request.setAttribute(HttpServletResponse.class.getName(), response);
    	// 获取已经创建的csrfToken对象，这个里tokenRespository可以自己定义。
        CsrfToken csrfToken = this.tokenRepository.loadToken(request);
       //...
```

![1617112824104](./img/1617112824104.png)

我们可以随便看一个实现。例如`CookieCsrfTokenRepository`

```java
public final class CookieCsrfTokenRepository implements CsrfTokenRepository {
    // 从cookie中获得地参数名
    static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";
    // 从http请求参数里获得参数名
    static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";
    // 从http header 获得csrftoken的属性名
    static final String DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN";
    private String parameterName = "_csrf";
    private String headerName = "X-XSRF-TOKEN";
    private String cookieName = "XSRF-TOKEN";
    private boolean cookieHttpOnly = true;
    private String cookiePath;
    private String cookieDomain;
    private Boolean secure;

    public CookieCsrfTokenRepository() {
    }
	// 封装了一个对象
    public CsrfToken generateToken(HttpServletRequest request) {
        							//X-XSRF-TOKEN     _csrf
        return new DefaultCsrfToken(this.headerName, this.parameterName, 
                                    // 这里往下翻就会找到内容，其实就是生成了一个uuid
                                    this.createNewToken());
    }
	// 直接就设置了一个cookie返回
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        String tokenValue = token != null ? token.getToken() : "";
        Cookie cookie = new Cookie(this.cookieName, tokenValue);
        cookie.setSecure(this.secure != null ? this.secure : request.isSecure());
        cookie.setPath(StringUtils.hasLength(this.cookiePath) ? this.cookiePath : this.getRequestContext(request));
        cookie.setMaxAge(token != null ? -1 : 0);
        cookie.setHttpOnly(this.cookieHttpOnly);
        if (StringUtils.hasLength(this.cookieDomain)) {
            cookie.setDomain(this.cookieDomain);
        }

        response.addCookie(cookie);
    }

    public CsrfToken loadToken(HttpServletRequest request) {
        // 直接从请求中获得带过来的cookie值，获取对应内容，如果没有就返回空
        Cookie cookie = WebUtils.getCookie(request, this.cookieName);
        if (cookie == null) {
            return null;
        } else {
            String token = cookie.getValue();
            //封装成对象返回
            return !StringUtils.hasLength(token) ? null : new DefaultCsrfToken(this.headerName, this.parameterName, token);
        }
    }
    // ...
    // 其实生成的就是一个uuid而已
    private String createNewToken() {
        return UUID.randomUUID().toString();
    }
}
```

回到csrf验证。

```java
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        request.setAttribute(HttpServletResponse.class.getName(), response);
        CsrfToken csrfToken = this.tokenRepository.loadToken(request);
        boolean missingToken = csrfToken == null;
        if (missingToken) {
            //没有找到token就生成一个，放到request的cookie中，方便下次请求携带
            csrfToken = this.tokenRepository.generateToken(request);
            //携带。
            this.tokenRepository.saveToken(csrfToken, request, response);
        }

        request.setAttribute(CsrfToken.class.getName(), csrfToken);
    	// _csrf
        request.setAttribute(csrfToken.getParameterName(), csrfToken);
    	// 是否匹配规则
        if (!this.requireCsrfProtectionMatcher.matches(request)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Did not protect against CSRF since request did not match " + this.requireCsrfProtectionMatcher);
            }
			// 不匹配就放行
            filterChain.doFilter(request, response);
        } else {
            // 从请求头获得token
            String actualToken = request.getHeader(csrfToken.getHeaderName());
            // 头没拿到，就去请求参数去拿
            if (actualToken == null) {
                actualToken = request.getParameter(csrfToken.getParameterName());
            }
			//如果拿到的相同，就放心，否则报错。
            if (!equalsConstantTime(csrfToken.getToken(), actualToken)) {
                this.logger.debug(LogMessage.of(() -> {
                    return "Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request);
                }));
                AccessDeniedException exception = !missingToken ? new InvalidCsrfTokenException(csrfToken, actualToken) : new MissingCsrfTokenException(actualToken);
                this.accessDeniedHandler.handle(request, response, (AccessDeniedException)exception);
            } else {
                // 符合，放行。
                filterChain.doFilter(request, response);
            }
        }
    }


// 符合csrf的过滤请求规则
 private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {
        private final HashSet<String> allowedMethods;

        private DefaultRequiresCsrfMatcher() {
            this.allowedMethods = new HashSet(Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));
        }
		// 只要符合上述的几个请求类型，就要进入csrf的流程。
        public boolean matches(HttpServletRequest request) {
            return !this.allowedMethods.contains(request.getMethod());
        }
```

当然这个是我们在单体架构中实现的csrf跨域攻击的防护，那如果我们是在前后端分离的项目中呢？这 个时候我们是可以将token信息保存在Http协议的Head中的， 浏览器索要登录页面的时候，服务器生成一个随机的csrf_token，放入cookie中。 

```
Set-Cookie: Csrf-token=i8XNjC4b8KVok4uw5RftR38Wgp2BFwql; .....
```

浏览器通过JavaScript读取cookie中的Csrf_token，然后在发送请求时作为自定义HTTP头发送回来。

```
X-Csrf-Token: i8XNjC4b8KVok4uw5RftR38Wgp2BFwql
```

![1617113798592](./img/1617113798592.png)

服务器读取HTTP头中的Csrf_token，与cookie中的Csrf_token比较，一致则放行，否则拒绝。 这种方法为什么能够防御CSRF攻击呢？ 关键在于JavaScript读取cookie中的Csrf_token这步。由于浏览器的同源策略，攻击者是无法从被 攻击者的cookie中读取任何东西的。所以，攻击者无法成功发起CSRF攻击。

#### remember-me功能

首先，只要登录成功才能进行`remember-me`的功能。
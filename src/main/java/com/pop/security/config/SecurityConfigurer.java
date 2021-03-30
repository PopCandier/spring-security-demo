package com.pop.security.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @program: security
 * @description:
 * @author: Pop
 * @create: 2021-03-30 20:53
 **/
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
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
                .defaultSuccessUrl("/home")//成功后跳转
                .failureUrl("/failure") // 失败的跳转
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .invalidateHttpSession(true)//注销会话
                .logoutSuccessUrl("/login")//注销成功后跳转页面
                .permitAll()
                .and()
                .csrf().disable();

    }
}

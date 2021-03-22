package com.pop.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @program: security
 * @description:
 * @author: Pop
 * @create: 2021-03-14 18:44
 **/
@Controller
public class HelloController {

    @PreAuthorize(value = "hasAnyAuthority('ROOT')")
    @GetMapping("/index")
    public String index(){
        return "index";
    }
    
}

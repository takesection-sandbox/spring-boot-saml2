/*
 * Copyright 2016 Pigumer Group Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jp.pigumer.sso;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@SpringBootApplication
@Controller
public class Application {
    
    @Autowired
    private MetadataManager metadata;
    
    private boolean isForwarded(HttpServletRequest request) {
        if (request.getAttribute("javax.servlet.forward.request_uri") == null) {
            return false;
        } else {
            return true;
        }
    }

    @RequestMapping(value = "/saml/idpSelection", method = RequestMethod.GET)
    public String idpSelection(HttpServletRequest request, Model model) {
        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
            return "redirect:/landing";
        } else {
            if (isForwarded(request)) {
                Set<String> idps = metadata.getIDPEntityNames();
                model.addAttribute("idps", idps);
                return "saml/idpselection";
            } else {
	        return "redirect:/";
            }
        }
    }
        
    @RequestMapping("/")
    String index(Model model) {
        model.addAttribute("hello", "/hello");
        return "index";
    }
    
    /**
     * /hello.
     * 
     * @param user User
     * @param model Model
     * @return hello
     */
    @RequestMapping("/hello")
    String hello(@CurrentUser User user, Model model) {
        model.addAttribute("user", user.getUsername());
        return "hello";
    }
    
    /**
     * main
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}

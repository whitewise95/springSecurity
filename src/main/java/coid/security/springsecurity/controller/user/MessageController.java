package coid.security.springsecurity.controller.user;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {
	
	@GetMapping(value="/messages")
	public String mypage() throws Exception {

		return "user/messages";
	}

	@ResponseBody
	@GetMapping("/api/messages")
	public String apiMessge(){
		return "messages ok";
	}
}

package coid.security.springsecurity.controller.user;


import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {
	
	@GetMapping(value="/messages")
	public String mypage() throws Exception {
		return "user/messages";
	}

	@ResponseBody
	@PostMapping("/api/messages")
	public ResponseEntity apiMessge(){
		return ResponseEntity.ok().body("ok");
	}
}

package com.community;

import com.community.web.domain.Board;
import com.community.web.domain.User;
import com.community.web.domain.enums.BoardType;
import com.community.web.repository.BoardRepository;
import com.community.web.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.time.LocalDateTime;

@SpringBootApplication
public class CommunityApplication {

	public static void main(String[] args) {
		SpringApplication.run(CommunityApplication.class, args);
	}

	/*@Bean
	public CommandLineRunner commandLineRunner(UserRepository userRepository, BoardRepository boardRepository) {
		return args -> {
			User user = User.builder().name("유현재").password("hj24").email("aaa@naver.com").createdDate(LocalDateTime.now()).build();

			userRepository.save(user);

			for (int i = 0; i < 156; i++) {
				boardRepository.save(Board.builder().title("타이틀"+i).subTitle("서브타이틀"+i).content("내용"+i).boardType(BoardType.free).createdDate(LocalDateTime.now()).user(user).build());
			}
		};
	}*/
}


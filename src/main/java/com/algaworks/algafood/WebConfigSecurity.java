package com.algaworks.algafood;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity //Opcional
public class WebConfigSecurity extends WebSecurityConfigurerAdapter{
	
	
	// CONFIGURAÇÕES DE ACESSO A API DE AUTENTICAÇÃO
	
	
	//Configurando usuário e senha em memória
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
				.withUser("patrick")
					.password(passwordEncoder().encode("123"))
					.roles("ADMIN")
			.and()
				.withUser("thais")
					.password(passwordEncoder().encode("123"))
					.roles("ADMIN");
	}
	
	//Um método que gera encoder
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();//vai encriptografar as senhas
	}
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	@Bean
	@Override
	protected UserDetailsService userDetailsService() {
		return super.userDetailsService();
	}
	
	
	/*COMO FUNCIONA NA REQUISIÇÃO
	 * 
	 * -> Faz um post no http://localhost:8081
	 * Na parte de autenticação, coloca o id e password para se autenticar no AuthenticationServer
	 * No corpo como parâmetro usando o content-type x-www-form-urlencoded coloca usuário e senha lá do algafood
	 * Isso irá gerar um token que será devolvido
	 */
		
	
	//NÃO PRECISA AQUI PQ ESSA CLASSE É APENAS AUTORIZATION SERVER
	
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.httpBasic()
//			.and()
//				.authorizeRequests()
//					.antMatchers("/cozinhas/**").permitAll()//permita sem requisição
//					.anyRequest().authenticated()//Autoriza quem está autenticado
//			.and()
//				.sessionManagement()
//					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)//diz que não vai ter session na aplicação
//			.and()
//				.csrf().disable();//Não iremos mais usar cookie. Vamos passar as credenciais todas as vezes
//	}

}

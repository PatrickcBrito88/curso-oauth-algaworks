package com.algaworks.algafood;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

import java.util.Arrays;

//ESSA CLASSE CONFIGURA O PROJETO PARA SER UM AUTORIZATION  SERVER

@Configuration
@EnableAuthorizationServer//Habilitou o projeto para ser um authorizationServer. Habilita os endpoints exclusivos do AutorizationServer Oauth/token
public class AutorizationServerConfig extends AuthorizationServerConfigurerAdapter{

	@Autowired
	private PasswordEncoder passwordEncoder; // Vem lá da classe WebConfigSecurity
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	//Para rodar na versão 11 do Java tem que incluir outras 3 dependências que estão no git do thiago. 
	//Já coloquei nesse projeto. São elas: groupBy é o mesmo: com.sun.xml.bind. ArtifactId: jaxb-api, jaxb-core e jaxb-impl
	
	//								----------------- CONFIGURAÇÕES DO CLIENTE -----------------------
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		//configurar quais clientes estão permitidos para receber um acess token
		
		clients.inMemory()//configurando cliente em memória
		
						//PARA UM CLIENTE SE CONECTAR AO AUTORIZATHION SERVER
						//CADA CLIENTE PODE TER UM GRANDTYPE
		
			.withClient("algafood-web")//Id do client (autenticação do cliente no autorization server)
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")//Granttypes são fluxos. Esse cliente, com essas credenciais, pode usar apenas o fluxo password
											//refreshtoken para gerar refresh_tokens
				.scopes("write","read")///Especificar quais são os scops possíveis
				.accessTokenValiditySeconds(6 * 60 * 60)//Tempo de validação d token ( 6 horas x 60 minutos x 60 segundos)
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60)// Tempo de validade do RefreshTokens (sem segundos) 60 dias no caso
			
			.and()
			.withClient("faturamento") //Client Credencials usado para outras aplicações back end
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")//Cliente Credencials não trabalha com refresh tokens
				.scopes("write","read")
				.accessTokenValiditySeconds(10)
				
			.and()
			.withClient("foodanalytics")
				.secret(passwordEncoder.encode(""))//Ficou sem senha, pois se usar o PKCE não precisa
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://www.foodanalytics.local:8082")//redirecionamento para o code autorization --Pode ter mais de uma
				/*
				 * Este grand-type retorna um code e a partir deste code solicita o token
				 * No navegador, digite: http://localhost:8081/oauth/
				 * authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://aplicacao-cliente
				 *
				 * Da maneira acima eu uso o autorizationCode normal. Da maneira abaixo eu uso com o PKCE com PLAIN
				 * http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=
				 * http://www.foodanalytics.local:8082&code_challenge=teste123&code_challenge_method=plain
				 *
				 * Da maneira abaixo eu uso com o PKCE com SHA256
				 * http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&redirect_uri=
				 * http://www.foodanalytics.local:8082&code_challenge=KQQKcWZ9NcPRsnowjhRd_H6xdZcO6sjth_1MWvKOc28&code_challenge_method=S256
				 * o code_challenge tem que passar por uma transformação para o code chalenge. No curso o thiago usou https://tonyxu-io.github.io/pkce-generator/
				 * 1º Gera um code_challenge e passa na Url
				 * 2º o Code_challenge possui um code verifier
				 * 3º~ No postman passamos o code_verifier no body
				 * 4º Gera o token
				 *
				 *
				 * Code_verifier: Tat7CUYGQiRo.K7h64Iz7_KqQMH2IFO~_sWUkMWO7VhUzcDzAuI2y21-WPnnvkVCRMblv1_m3.7HhtbCkZes5X0IRZugNl-dGpG~2608YrnpMpKIXXwJVgThXKZjtyP8
				 * code_Challenge: F1oUhZ779qjsS1MJP-e6ohmKT49IZK_8a0SjQZ-Ktlc
				 *
				 *
				 * Este link irá direcionar para uma tela de login. Depois do login vai solicitar permissão de escrita e leitura
				 * Após autorização, ele redireciona para o redirect_uri com o code. Este code serve para pegar o token e acessar
				 * 
				 */
			.and()
			.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write","read")
				.redirectUris("http://aplicacao-cliente-implicit")//Semelhante ao authorization code. Tem que ter pelo menos uma URL de redirecionamento
				/*
				 * URL para acesso: http://localhost:8081/oauth/
				 * authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente-implicit
				 */
				
		
			.and()
			.withClient("checktoken") //login e senha exclusivo pro Resourceserver se autenticar
				.secret(passwordEncoder.encode("check123"));
		
	}

	//Gera tokenGranter tem a configuraçao de todos os TokenGranters (Autorization, Implicit, client_credencials)
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());

		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

		return new CompositeTokenGranter(granters);
	}

	
	//							---------------- CONFIGURAÇÕES DO ENDPOINT -----------------------

	//Este método especifica um authenticationManager para o AutorizationServerConfig
	//Somente este fluxo password precisa deste authorizationserverendpoint, pois é através dele que o autorizationserver valida
	//o usuário e senha do usuário final que é passado via API se não o Passwordflow não funciona
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
				.authenticationManager(authenticationManager)//Somente o PasswordFlow precisa do authenticationManager
				.userDetailsService(userDetailsService)
				.reuseRefreshTokens(false) //Não permite reutilizar o refresh tokens -- Utilizado apenas uma vez -- A cada utilização gera um novo RefreshToken
				.tokenGranter(tokenGranter(endpoints)); //Adiciona suporte a token Granter no autorizationServer

		//O authenticationmanager é gerado na classe webconfigsecurity por bean
		//o autorizationserviceconfig precisa do userDetailsService para funcionar
		
		
	}
	
	//					------------------- CONFIGURAÇÕES DE SEGURANÇA -----------------------

	//Endpoint que verifica se permite utilizar o check e verificar se o token está válido
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");//Para acessar o endpoint de checktoken tem que que estar autenticado
		security.checkTokenAccess("permitAll") //Não precisa de autenticação para fazer um check token
				.allowFormAuthenticationForClients();//Permite autenticação direto no body
		//Para verificar o token tem que configurar o Basic security com o id e password de
		//acesso ao autorizationServerConfig (Lembra que esse acesso é via Basic Security?
	}
	
	
}

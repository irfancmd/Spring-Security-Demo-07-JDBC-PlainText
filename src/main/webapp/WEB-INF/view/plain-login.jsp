<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Custom Login Page</title>

<style>
	.failed {
		color: red;	
	}
</style>
</head>
<body>
	<h3>My Custom Login Page</h3>
	
	<form:form action="${pageContext.request.contextPath}/authenticateTheUser" method="POST">

		<!-- Check for login error -->
		<c:if test="${param.error != null}">
			<i class="failed">Invalid user name or password</i>
		</c:if>		
	
		
		<!-- The inputs should be named accordingly if we want spring security to automatically handle them -->
		<p>
			User name: <input type="text" name="username"/>	
		</p>	
		<p>
			Password: <input type="password" name="password"/>	
		</p>
		<input type="submit" value="Login"/>	
	</form:form>	
</body>
</html>
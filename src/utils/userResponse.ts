export const UserResponseExample = {
  message: 'Success',
  data: {
    user: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin',
      isVerified: false,
      image: null
    },
    token: 'block token'
  }
}

export const LoginResponseExample = {
  message: 'Success',
  data: {
    accessToken: 'accessToken',
    refreshToken: 'refreshToken',
    user: {
      email: 'george.asiedu@gmail.com',
      name: 'George Asiedu',
      role: 'Admin',
      isVerified: true,
      image: null
    }
  }
}

export const GetAllUsersResponseExample = {
  message: 'Success',
  data: [
    {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin',
      refreshToken: null,
      isVerified: true
    }
  ]
}

export const BadRequestExample = [
  'name should not be empty',
  'email must be an email',
  'password must be at least 8 characters long'
]

export const LoginBadRequestExample = [
  'email must be an email',
  'password must be at least 8 characters long'
]

export const RegularLoginExample = {
  summary: 'Regular Login',
  value: { email: 'george.asiedu@gmail.com', password: 'password123', rememberMe: false },
}

export const RememberMeLoginExample = {
  summary: 'Login with Remember Me',
  value: { email: 'george.asiedu@gmail.com', password: 'password123', rememberMe: true },
}
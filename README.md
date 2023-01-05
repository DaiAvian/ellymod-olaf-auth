# Olaf Authentication

## Project setup

```
npm install @ellymod/olaf-auth
```


### Add a service to your file

```js
import {AuthService} from "@ellymod/olaf-auth/lib"
```

### Initialize an instance and reference a method

```js
const olafService = new AuthService(config)
olafService.loginWithRedirect()
```

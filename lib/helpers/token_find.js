export function createTokenFinder(provider, grantTypeHandlers, { strict = false } = {}) {
  const { AccessToken, ClientCredentials, RefreshToken } = provider;

  function getAccessToken(token) {
    return AccessToken.find(token);
  }

  function getClientCredentials(token) {
    if (!grantTypeHandlers.has('client_credentials')) {
      return undefined;
    }
    return ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    if (!grantTypeHandlers.has('refresh_token')) {
      return undefined;
    }
    return RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find((found) => !!found);
  }

  // fork: `strict` chỉ chặn fallback RA NGOÀI nhóm của hint, không chia nhỏ bên
  // trong nhóm. Với strict === false hàm này tương đương từng bước bản upstream.
  //
  // Cờ là THAM SỐ, không đọc config trực tiếp, vì createTokenFinder được dùng
  // bởi cả introspection.js và revocation.js — chỉ introspection truyền vào,
  // nên hành vi revocation không đổi.
  return async function findTokenByHint(tokenValue, tokenTypeHint) {
    switch (tokenTypeHint) {
      case 'access_token':
      case 'urn:ietf:params:oauth:token-type:access_token': {
        const inGroup = await Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
        ]).then(findResult);
        if (inGroup || strict) return inGroup;
        return getRefreshToken(tokenValue);
      }
      case 'refresh_token':
      case 'urn:ietf:params:oauth:token-type:refresh_token': {
        const inGroup = await getRefreshToken(tokenValue);
        if (inGroup || strict) return inGroup;
        return Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
        ]).then(findResult);
      }
      default:
        return Promise.all([
          getAccessToken(tokenValue),
          getClientCredentials(tokenValue),
          getRefreshToken(tokenValue),
        ]).then(findResult);
    }
  };
}

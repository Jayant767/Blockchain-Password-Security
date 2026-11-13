export async function api(path, options={}) {
  const csrf = document.cookie.split('; ').find(v=>v.startsWith('bps_csrf='))?.split('=').slice(1).join('=');
  const headers={ 'Content-Type':'application/json', ...(options.headers||{}) };
  if(options.method && options.method!=='GET' && csrf) headers['X-CSRF-Token']=decodeURIComponent(csrf);
  const response=await fetch(`/api${path}`,{credentials:'include',...options,headers});
  if(response.status===204) return null;
  const data=await response.json().catch(()=>({}));
  if(!response.ok) throw new Error(data.error?.message || 'Request failed');
  return data;
}

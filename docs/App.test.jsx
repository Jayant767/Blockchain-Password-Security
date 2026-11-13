import React from 'react';
import { describe,it,expect,vi,beforeEach } from 'vitest';
import { render,screen,fireEvent,waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import App from './App';
import { api } from './api';
vi.mock('./api',()=>({api:vi.fn()}));
describe('frontend authentication flows',()=>{
  beforeEach(()=>api.mockReset());
  it('renders the landing page and secure authentication positioning',()=>{
    api.mockRejectedValue(new Error('no session'));
    render(<MemoryRouter><App/></MemoryRouter>);
    expect(screen.getByText(/Password security,/i)).toBeInTheDocument();
    expect(screen.getByText(/Argon2id protects credentials off-chain/i)).toBeInTheDocument();
  });
  it('submits the login form and navigates to the protected dashboard',async()=>{
    let meCalls=0;
    const user={id:'u1',email:'student@example.com',credentialVersion:1,createdAt:new Date().toISOString()};
    api.mockImplementation(async path=>{
      if(path==='/users/me'){meCalls++;if(meCalls===1)throw new Error('no session');return {user};}
      if(path==='/auth/login')return {user};
      if(path==='/blockchain/status')return {available:false};
      if(path==='/audit/history')return {events:[]};
      return {};
    });
    render(<MemoryRouter initialEntries={['/login']}><App/></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/Email address/i),{target:{value:'student@example.com'}});
    fireEvent.change(screen.getByLabelText(/Password/i),{target:{value:'correct horse battery staple'}});
    fireEvent.click(screen.getByRole('button',{name:/Sign in/i}));
    await waitFor(()=>expect(screen.getByText(/Good to see you/i)).toBeInTheDocument());
    expect(api).toHaveBeenCalledWith('/auth/login',expect.objectContaining({method:'POST'}));
  });
});

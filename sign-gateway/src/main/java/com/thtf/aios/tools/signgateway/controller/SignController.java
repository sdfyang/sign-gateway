package com.thtf.aios.tools.signgateway.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.thtf.aios.tools.signgateway.model.PublicKeyInfo;
import com.thtf.aios.tools.signgateway.service.SignService;

@Controller
public class SignController
{
	@Autowired
	protected SignService signService;

	@ResponseBody
	@RequestMapping(value = "/publickeys")
	public PublicKeyInfo[] getPublicKeys()
	{
		return signService.getPublicKeys();
	}

	@ResponseBody
	@RequestMapping(value = "/sign", method = RequestMethod.POST)
	public byte[] sign(String keyname, @RequestBody byte[] data)
	{
		return signService.sign(data, keyname);
	}
}

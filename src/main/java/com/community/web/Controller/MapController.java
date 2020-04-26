package com.community.web.Controller;

import java.io.File;
import java.io.FileReader;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MapController {
	private static final Logger logger = LoggerFactory.getLogger(MapController.class);
	

	@GetMapping(value = "/map")
	public String map(Model model) {
		
		
		
		return "map";
	}
	
	@RequestMapping(value = "/ajaxMap",method = RequestMethod.POST)
	@ResponseBody
	public JSONObject ajaxMap(@RequestBody String data) throws Exception{
		
		JSONParser parser = new JSONParser();
		
		JSONObject jobj = null;
		
		try {
			Object obj = parser.parse(new FileReader("./src/main/resources/static/JSON/qgisMap.geojson"));
			
			jobj = (JSONObject) obj;
			
		} catch (Exception e) {
			logger.info(e.toString());
		}
		
		return jobj;
	}
}

package com.thtf.aios.tools.signgateway.service.impl;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileSystem
{
	public static ArrayList<String> parsePath(String pathname)
	{
		ArrayList<String> path = new ArrayList<String>();

		String[] result = pathname.split("\\/");
		for(int index = 0; index != result.length; ++index)
		{
			path.add(result[index]);
		}

		return path;
	}

	public static String makePath(List<String> path)
	{
		StringBuilder builder = new StringBuilder();

		for(int index = 0; index != path.size(); ++index)
		{
			if (index != 0)
				builder.append('/');

			builder.append(path.get(index));
		}

		return builder.toString();
	}

	public static int copyFile(File src, File dst)
		throws IOException
	{
		int bytecount = 0;

		if (dst.exists())
			dst.delete();

		dst.createNewFile();

		FileInputStream input = new FileInputStream(src);
		FileOutputStream output = new FileOutputStream(dst);

		byte[] buffer = new byte[256];

		while(input.available() > 0)
		{
			int count = input.read(buffer);

			output.write(buffer, 0, count);

			bytecount += count;
		}

		output.close();
		input.close();

		return bytecount;
	}

	public static int copyAll(File src, File dst)
		throws IOException
	{
		int filecount = 0;

		if (src.isFile())
		{
			copyFile(src, dst);
			return 1;
		}

		if (src.isDirectory())
		{
			dst.mkdirs();

			for(File child: src.listFiles())
			{
				File target = new File(dst, child.getCanonicalPath());

				filecount += copyAll(child, target);
			}
		}

		return filecount;
	}

	public static byte[] readBytes(InputStream input)
	{
		byte[] bytes = new byte[256];
        int count = 0;

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try
        {
	        while(true)
	        {
	            count = input.read(bytes);
	            if (count == -1)
	                break;
	
	            output.write(bytes, 0, count);
	        }
	
	        output.close();
        } catch(Exception e)
        {
        	e.printStackTrace();
        }

        return output.toByteArray();
	}

	public static byte[] readBytes(File file)
	{
		byte[] data = null;

		if (file.exists())
		{
			try
			{
				FileInputStream input = new FileInputStream(file);
				
				data = readBytes(input);
				
				input.close();
			} catch(Exception e)
			{
				e.printStackTrace();
			}
		}
		
		return data;
	}

	public static String readString(InputStream input, String encoding)
	{
		String content = null;
		
		byte[] data = readBytes(input);

		
		if (data != null)
		{
			try
			{
				content = new String(data, encoding);
			} catch(Exception e)
			{
				e.printStackTrace();
			}
		}
		
		return content;
	}

	public static String readString(File file, String encoding)
	{
		String content = null;
		
		byte[] data = readBytes(file);

		
		if (data != null)
		{
			try
			{
				content = new String(data, encoding);
			} catch(Exception e)
			{
				e.printStackTrace();
			}
		}
		
		return content;
	}

	public static boolean writeData(File file, InputStream input)
	{
		try
		{
			if (file.exists())
				file.delete();
			
			file.createNewFile();

			FileOutputStream output = new FileOutputStream(file);
			
			if (input != null)
				writeData(output, input);
			
			output.close();
			
			return true;
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}
	
	public static boolean writeData(OutputStream output, InputStream input)
	{
		byte[] bytes = new byte[256];
		int count = 0;
		
		try
		{
			while(true)
			{
				count = input.read(bytes);
				if (count == -1)
					break;
				
				output.write(bytes, 0, count);
			}
			
			return true;
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}

	public static boolean writeBytes(File file, byte[] data)
	{
		try
		{
			if (file.exists())
				file.delete();
			
			file.createNewFile();
			
			
			FileOutputStream output = new FileOutputStream(file);
			
			if (data != null)
				output.write(data);
			
			output.close();
			
			return true;
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}

	public static boolean writeBytes(OutputStream output, byte[] data)
	{
		try
		{			
			if (data != null)
				output.write(data);
			
			return true;
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}

	public static boolean writeString(
		File file, String content, String encoding)
	{
		try
		{
			writeBytes(file, content.getBytes(encoding));

			return true;
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}
	
	public static boolean writeString(
		OutputStream output, String content, String encoding)
	{
		try
		{
			writeBytes(output, content.getBytes(encoding));

			return true;
		} catch(Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}
}

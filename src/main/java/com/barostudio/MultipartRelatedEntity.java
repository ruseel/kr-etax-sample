package com.barostudio;

import java.nio.charset.Charset;

import org.apache.http.entity.mime.MultipartEntity;

class MultipartRelatedEntity extends MultipartEntity {
	@Override
	protected String generateContentType(String boundary, Charset charset) {
		StringBuilder buffer = new StringBuilder();
        buffer.append("multipart/related");
        buffer.append("; type=\"text/xml\"");
        buffer.append("; start=\"<SOAPPart>\"");
        buffer.append("; boundary=\"");
        buffer.append(boundary);
        buffer.append("\"");
        if (charset != null) {
            buffer.append("; charset=");
            buffer.append(charset.name());
        }
        return buffer.toString();
	}
}
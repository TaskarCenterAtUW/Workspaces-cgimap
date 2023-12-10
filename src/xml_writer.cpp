/**
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This file is part of openstreetmap-cgimap (https://github.com/zerebubuth/openstreetmap-cgimap/).
 *
 * Copyright (C) 2009-2023 by the CGImap developer community.
 * For a full list of authors see the git log.
 */

#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <memory>
#include <stdexcept>
#include <iostream>
#include <utility>
#include "cgimap/xml_writer.hpp"

struct xml_writer::pimpl_ {
  xmlTextWriterPtr writer;
};

xml_writer::xml_writer(const std::string &file_name, bool indent)
    : pimpl(std::make_unique<pimpl_>()) {
  // allocate the text writer "object"
  pimpl->writer = xmlNewTextWriterFilename(file_name.c_str(), 0);

  // check the return value
  if (pimpl->writer == NULL) {
    throw std::runtime_error("error creating xml writer.");
  }

  init(indent);
}

static int wrap_write(void *context, const char *buffer, int len) {
  auto *out = static_cast<output_buffer *>(context);

  if (out == nullptr) {
    throw xml_writer::write_error("Output buffer was NULL in wrap_write().");
  }

  return out->write(buffer, len);
}

static int wrap_close(void *context) {
  auto *out = static_cast<output_buffer *>(context);

  if (out == nullptr) {
    throw xml_writer::write_error("Output buffer was NULL in wrap_close().");
  }

  return out->close();
}

// create a new XML writer using writer callback functions
xml_writer::xml_writer(output_buffer &out, bool indent)
    : pimpl(std::make_unique<pimpl_>()) {
  xmlOutputBufferPtr output_buffer =
      xmlOutputBufferCreateIO(wrap_write, wrap_close, &out, NULL);

  // allocate a writer using the output buffer object
  pimpl->writer = xmlNewTextWriter(output_buffer);

  // check the return value
  if (pimpl->writer == NULL) {
    // free the output buffer
    free(output_buffer);

    throw std::runtime_error("error creating xml writer.");
  }

  init(indent);
}

void xml_writer::init(bool indent) {
  // maybe enable indenting
  if (indent) {
    xmlTextWriterSetIndent(pimpl->writer, 1);
  }

  // start the document
  if (xmlTextWriterStartDocument(pimpl->writer, NULL, "UTF-8", NULL) < 0) {
    throw write_error("error creating document element.");
  }
}

xml_writer::~xml_writer() noexcept {
  // close and flush the xml writer object. note - if this fails then
  // there isn't much we can do, as this object is going to be deleted
  // anyway.
  try {
    xmlTextWriterEndDocument(pimpl->writer);
  } catch (...) {
    // don't do anything here or we risk FUBARing the entire program.
    // it might not be possible to end the document because the output
    // stream went away. if so, then there is nothing to do but try
    // and reclaim the extra memory.
  }
  xmlFreeTextWriter(pimpl->writer);
}

void xml_writer::start(const char *name) {
  if (xmlTextWriterStartElement(pimpl->writer, reinterpret_cast<const xmlChar *>(name)) < 0) {
    throw write_error("cannot start element.");
  }
}

void xml_writer::attribute(const char *name, const std::string &value) {
  int rc = writeAttribute(name, value.c_str());
  if (rc < 0) {
    throw write_error("cannot write attribute.");
  }
}

void xml_writer::attribute(const char *name, const char *value) {
  const char *c_str = value ? value : "";
  int rc = writeAttribute(name, c_str);
  if (rc < 0) {
    throw write_error("cannot write attribute.");
  }
}

void xml_writer::attribute(const char *name, double value) {
  int rc = xmlTextWriterWriteFormatAttribute(
    pimpl->writer,
    reinterpret_cast<const xmlChar *>(name),
    "%.7f",
    value);
  if (rc < 0) {
    throw write_error("cannot write double-precision attribute.");
  }
}

void xml_writer::attribute(const char *name, bool value) {
  const char *str = value ? "true" : "false";
  int rc = writeAttribute(name, str);
  if (rc < 0) {
    throw write_error("cannot write boolean attribute.");
  }
}

void xml_writer::text(const char* t) {
  if (xmlTextWriterWriteString(pimpl->writer, reinterpret_cast<const xmlChar *>(t)) < 0) {
    throw write_error("cannot write text string.");
  }
}

void xml_writer::end() {
  if (xmlTextWriterEndElement(pimpl->writer) < 0) {
    throw write_error("cannot end element.");
  }
}

void xml_writer::flush() {
  if (xmlTextWriterFlush(pimpl->writer) < 0) {
    throw write_error("cannot flush output stream");
  }
}

void xml_writer::error(const std::string &s) {
  start("error");
  text(s);
  end();
}

int xml_writer::writeAttribute(const char* name, const char* value) {
  int rc = xmlTextWriterWriteAttribute(
    pimpl->writer,
    reinterpret_cast<const xmlChar *>(name),
    reinterpret_cast<const xmlChar *>(value));
  return rc;
}

// TODO: move this to its own file

xml_writer::write_error::write_error(const char *message)
    : std::runtime_error(message) {}

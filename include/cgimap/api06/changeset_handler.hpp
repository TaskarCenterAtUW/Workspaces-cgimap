/**
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This file is part of openstreetmap-cgimap (https://github.com/zerebubuth/openstreetmap-cgimap/).
 *
 * Copyright (C) 2009-2023 by the CGImap developer community.
 * For a full list of authors see the git log.
 */

#ifndef API06_CHANGESET_HANDLER_HPP
#define API06_CHANGESET_HANDLER_HPP

#include "cgimap/handler.hpp"
#include "cgimap/osm_current_responder.hpp"
#include "cgimap/request.hpp"
#include <string>

namespace api06 {

class changeset_responder : public osm_current_responder {
public:
  changeset_responder(mime::type, osm_changeset_id_t, bool, data_selection &);
};

class changeset_handler : public handler {
public:
  changeset_handler(request &req, osm_changeset_id_t id);

  std::string log_name() const override;
  responder_ptr_t responder(data_selection &x) const override;

private:
  osm_changeset_id_t id;
  bool include_discussion;
};

} // namespace api06

#endif /* API06_CHANGESET_HANDLER_HPP */

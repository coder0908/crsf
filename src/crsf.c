/*
 * crsf.c
 *
 *  Created on: Nov 13, 2025
 *      Author: coder0908
 */

#include "crsf.h"
#include <assert.h>

/*
 * sync_char(1), len(1), type(1), payload(len-2), crc(1)
 *
 * len : includes 'type', 'payload','crc'
 * crc : include 'type', 'payload'
 * */

static uint32_t buf_to_u32_little_endian(const uint8_t* buf)
{
	return (uint32_t)buf[3] | ((uint32_t)buf[2] << 8) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[0] << 24);
}

static uint32_t buf_to_u24_little_endian(const uint8_t* buf)
{
	return (uint32_t)buf[2] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[0] << 16);
}

static uint16_t buf_to_u16_little_endian(const uint8_t* buf)
{
	return buf[1] | (buf[0] << 8);
}

static void u16_to_buf_big_endian(uint8_t *buf, uint16_t value)
{
	buf[0] = value >> 8;
	buf[1] = value & 0xff;
}

static void u24_to_buf_big_endian(uint8_t *buf, uint32_t value)
{
	buf[0] = value >> 16;
	buf[1] = (value >> 8) & 0xff;
	buf[2] = value & 0xff;
}

static void u32_to_buf_big_endian(uint8_t *buf, int32_t value)
{
	buf[0] = value >> 24;
	buf[1] = (value >> 16) & 0xff;
	buf[2] = (value >> 8) & 0xff;
	buf[3] = value & 0xff;
}

static uint8_t crsf_crc8_dvbs2(uint8_t crc, uint8_t val)
{
	crc ^= val;
	for (int j = 0; j < 8; j++) {
		if (crc & 0x80) {
			crc = (crc << 1) ^ 0xD5;

		} else {
			crc <<= 1;
		}
	}
	return crc;
}

uint8_t crsf_calc_crc8_buf(const uint8_t *buf, uint8_t len)
{
	assert(buf);

	uint8_t crc = 0;
	for (uint8_t i=2; i<len-1; i++) {
		crc = crsf_crc8_dvbs2(crc, buf[i]);
	}
	return crc;
}

uint8_t crsf_calc_crc8_frame(const struct crsf_frame *frame)
{
	assert(frame);

	const uint8_t *const payload = frame->payload;
	uint8_t crc = 0;
	crc = crsf_crc8_dvbs2(crc, (uint8_t)frame->type);

	for (uint8_t i=0; i<frame->len-(CRSF_LEN_TYPE+CRSF_LEN_CRC); i++) {
		crc = crsf_crc8_dvbs2(crc, payload[i]);
	}
	return crc;
}

bool crsf_init_frame_queue(struct crsf_frame_queue *queue)
{
	assert(queue);

	queue->len = 0;
	queue->head = 0;

	return true;
}

bool crsf_push_frame_queue(struct crsf_frame_queue *queue, const struct crsf_frame *frame)
{
	assert(queue);
	assert(queue->len <= CRSF_FRAMESLEN_MAX);

	if (queue->len == CRSF_FRAMESLEN_MAX) {
		return false;
	}

	struct crsf_frame *const dest = queue->frames + (queue->head + queue->len) % CRSF_FRAMESLEN_MAX;
	*dest = *frame;
	queue->len += 1;

	return true;
}

bool crsf_pop_frame_queue(struct crsf_frame_queue *queue, struct crsf_frame *frame)
{
	assert(queue);
	assert(frame);

	if (queue->len == 0) {
		return false;
	}

	struct crsf_frame *src = queue->frames + queue->head;
	*frame = *src;
	queue->len -= 1;
	queue->head = (queue->head + 1) % CRSF_FRAMESLEN_MAX;

	return true;
}

bool crsf_parse_frame(struct crsf_frame *frame, const uint8_t *buf, uint8_t buf_len, uint8_t *read_len)
{
	if (buf_len < CRSF_LEN_METADATA) {
		*read_len = buf_len;
		return false;
	}
	if (buf[0] != CRSF_SYNC_CHAR) {
		*read_len = 1;
		return false;
	}
	if (buf[1] < 2) {
		*read_len = 2;
		return false;
	}
	if (buf_len < buf[1] + 2 || CRSF_PLDLEN_MAX + 2 < buf[1]) {
		*read_len = buf_len;
		return false;
	}

	frame->len = buf[1];
	frame->type = buf[2];

	uint8_t len = frame->len;

	uint8_t crc = crsf_calc_crc8_buf(buf, len + CRSF_LEN_SYNC + CRSF_LEN_LEN);
	if (buf[len + 1] != crc) {
		*read_len = buf[1] + 2;
		return false;
	}
	frame->crc = crc;

	for (int i=0; i<len-(CRSF_LEN_TYPE + CRSF_LEN_CRC); i++) {
		frame->payload[i] = buf[3 + i];
	}

	*read_len = len + CRSF_LEN_SYNC + CRSF_LEN_LEN;
	return true;
}

void crsf_parse_frames(struct crsf_frame_queue *queue, const uint8_t *buf, uint8_t buf_len, uint8_t *read_len)
{
	assert(queue);
	assert(buf);
	assert(read_len);

	struct crsf_frame frame;
	uint8_t tmp_read_len;
	uint8_t total_read_len;
	bool is_parse_success;

	for (total_read_len=0; total_read_len<buf_len; /*intentionally do nothing*/) {
		is_parse_success = crsf_parse_frame(&frame, buf + total_read_len, buf_len - total_read_len, &tmp_read_len);

		total_read_len += tmp_read_len;
		if (is_parse_success) {
			if (!crsf_push_frame_queue(queue, &frame)) {
				break;
			}
		}
	}
	*read_len = total_read_len;
}


bool crsf_flush_frmae_queue(struct crsf_frame_queue *queue)
{
	assert(queue);

	queue->len = 0;

	return true;
}

bool crsf_parse_gps(const struct crsf_frame *frame, struct crsf_gps *gps)
{
	assert(frame);
	assert(gps);

	if (frame->type != CRSF_TYPE_GPS) {
		return false;
	}

	if (frame->len != CRSF_PLDLEN_GPS + CRSF_LEN_TYPE + CRSF_LEN_CRC) {
		return false;
	}

	const uint8_t *const payload = frame->payload;

	gps->latitude_100ndeg = buf_to_u32_little_endian(payload);
	gps->longitude_100ndeg = buf_to_u32_little_endian(payload+4);
	gps->groundspeed_damph = buf_to_u16_little_endian(payload+8);
	gps->heading_cdeg = buf_to_u16_little_endian(payload+10);
	gps->alti_m = buf_to_u16_little_endian(payload+12);
	gps->satellites = payload[14];

	gps->alti_m -= 1000;

	return true;
}

bool crsf_parse_rc_channels(const struct crsf_frame *frame, struct crsf_rc_channels *rc_channels)
{
	assert(frame);
	assert(rc_channels);

	if (frame->type != CRSF_TYPE_RC_CHANNELS) {
		return false;
	}

	if (frame->len != CRSF_PLDLEN_RC_CHANNELS + CRSF_LEN_TYPE + CRSF_LEN_CRC) {
		return false;
	}

	const struct crsf_rc_channels *tmp = (struct crsf_rc_channels*)(frame->payload);
	*rc_channels = *tmp;

	return true;
}

bool crsf_parse_attitude(const struct crsf_frame *frame, struct crsf_attitude *attitude)
{
	assert(frame);
	assert(attitude);

	if (frame->type != CRSF_TYPE_GPS) {
		return false;
	}

	if (frame->len != CRSF_PLDLEN_ATTITUDE + CRSF_LEN_TYPE + CRSF_LEN_CRC) {
		return false;
	}

	const uint8_t *const payload = frame->payload;

	attitude->pitch_angle_100urad = buf_to_u16_little_endian(payload);
	attitude->roll_angle_100urad = buf_to_u16_little_endian(payload+2);
	attitude->yaw_angle_100urad = buf_to_u16_little_endian(payload+4);

	return true;
}

void crsf_framing_gps(struct crsf_frame *frame, int32_t latitude_100ndeg, int32_t longitude_100ndeg,
		uint16_t groundspeed_damph, uint16_t heading_cdeg, uint16_t altitude_m, uint8_t satellites)
{
	assert(frame);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_GPS + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_GPS;

	uint8_t *const payload = frame->payload;

	u32_to_buf_big_endian(payload, latitude_100ndeg);
	u32_to_buf_big_endian(payload+4, longitude_100ndeg);
	u16_to_buf_big_endian(payload+8, groundspeed_damph);
	u16_to_buf_big_endian(payload+10, heading_cdeg);
	u16_to_buf_big_endian(payload+12, altitude_m+1000);
	payload[14] = satellites;

	frame->crc = crsf_calc_crc8_frame(frame);
}

void crsf_framing_gps_ex(struct crsf_frame *frame, uint8_t fix_type, int16_t northward_velocity_cmps, int16_t eastward_velocity_cmps,
		int16_t vertical_velocity_cmps, int16_t horizontal_velocity_accuracy_cmps, int16_t track_accuracy_deg, int16_t alti_ellipsoid_m,
		int16_t horizontal_accuracy_cm, int16_t vertical_accuracy_cm, uint8_t horizontal_dop_deci, uint8_t vertical_dop_deci)
{
	assert(frame);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_GPS_EX + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_GPS_EX;

	uint8_t *const payload = frame->payload;

	payload[0] = fix_type;
	u16_to_buf_big_endian(payload+1, northward_velocity_cmps);
	u16_to_buf_big_endian(payload+3, eastward_velocity_cmps);
	u16_to_buf_big_endian(payload+5, vertical_velocity_cmps);
	u16_to_buf_big_endian(payload+7, horizontal_velocity_accuracy_cmps);
	u16_to_buf_big_endian(payload+9, track_accuracy_deg);
	u16_to_buf_big_endian(payload+11, alti_ellipsoid_m);
	u16_to_buf_big_endian(payload+13, horizontal_accuracy_cm);
	u16_to_buf_big_endian(payload+15, vertical_accuracy_cm);
	payload[17] = 0;
	payload[18] = horizontal_dop_deci;
	payload[19] = vertical_dop_deci;

	frame->crc = crsf_calc_crc8_frame(frame);
}

void crsf_framing_gps_time(struct crsf_frame *frame, int16_t year, uint8_t month, uint8_t day, uint8_t hour, uint8_t minuate, uint8_t second, uint8_t millisecond)
{
	assert(frame);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_GPS_TIME + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_GPS_TIME;

	uint8_t *const payload = frame->payload;


	u16_to_buf_big_endian(payload, year);
	payload[2] = month;
	payload[3] = day;
	payload[4] = hour;
	payload[5] = minuate;
	payload[6] = second;
	u16_to_buf_big_endian(payload+7, millisecond);

	frame->crc = crsf_calc_crc8_frame(frame);
}

void crsf_framing_attitude(struct crsf_frame *frame, int16_t pitch_angle_100urad, int16_t roll_angle_100urad, int16_t yaw_angle_100urad)
{
	assert(frame);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_ATTITUDE + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_ATTITUDE;

	uint8_t *const payload = frame->payload;


	u16_to_buf_big_endian(payload, pitch_angle_100urad);
	u16_to_buf_big_endian(payload+2, roll_angle_100urad);
	u16_to_buf_big_endian(payload+4, yaw_angle_100urad);

	frame->crc = crsf_calc_crc8_frame(frame);
}



void crsf_framing_variometer(struct crsf_frame *frame, int16_t vertical_velocity_cmps)
{
	assert(frame);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_VARIOMETER + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_VARIOMETER;

	uint8_t *const payload = frame->payload;

	u16_to_buf_big_endian(payload, vertical_velocity_cmps);

	frame->crc = crsf_calc_crc8_frame(frame);
}

void crsf_framing_battery(struct crsf_frame *frame, int16_t voltage_10uv, int16_t current_10ua, uint32_t capacity_used_mah, uint8_t remaining_percet)
{
	assert(frame);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_BATTERY + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_BATTERY;

	uint8_t *const payload = frame->payload;

	u16_to_buf_big_endian(payload, voltage_10uv);
	u16_to_buf_big_endian(payload+2, current_10ua);
	u24_to_buf_big_endian(payload+4, capacity_used_mah);
	payload[7] = remaining_percet;

	frame->crc = crsf_calc_crc8_frame(frame);
}

void crsf_framing_voltages(struct crsf_frame *frame, uint8_t voltage_src_id, uint16_t voltages_mv[], uint8_t voltages_len)
{
	assert(frame);
	assert(voltages_mv);
	assert(voltages_len <= 29);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_VOLTAGES(voltages_len) + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_VOLTAGES;

	uint8_t *const payload = frame->payload;

	payload[0] = voltage_src_id;
	uint8_t voltages_idx;
	for (voltages_idx=0; voltages_idx<voltages_len; voltages_idx++) {
		u16_to_buf_big_endian(payload+1+(voltages_idx*2), voltages_mv[voltages_idx]);
	}

	frame->crc = crsf_calc_crc8_frame(frame);
}

void crsf_framing_temps(struct crsf_frame *frame, uint8_t temp_src_id, int16_t temps_ddeg[], uint8_t temps_len)
{
	assert(frame);
	assert(temps_ddeg);
	assert(temps_len <= 20);

	frame->sync = CRSF_SYNC_CHAR;
	frame->len = CRSF_PLDLEN_TEMPS(temps_len) + CRSF_LEN_TYPE + CRSF_LEN_CRC;
	frame->type = CRSF_TYPE_TEMPS;

	uint8_t *const payload = frame->payload;

	payload[0] = temp_src_id;
	uint8_t temps_idx;
	for (temps_idx=0; temps_idx<temps_len; temps_idx++) {
		u16_to_buf_big_endian(payload+1+(temps_idx*2), temps_ddeg[temps_idx]);
	}

	frame->crc = crsf_calc_crc8_frame(frame);
}

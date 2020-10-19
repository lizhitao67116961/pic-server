/*
 * imgzip.h
 *
 *  Created on: 2013-02-27
 *      Author: lizhitao
 */
#include "../imgzip_config.h"
#include "../imgzip_core.h"

#ifndef IMGZIP_H_
#define IMGZIP_H_
#include <magick/api.h>
#include <wand/magick_wand.h>
#include <magick/image.h>
#define IMG_MAX_WIDTH 740
#define IMG_MAX_HEIGHT 740
#define ADD_WATER_MIN_SIZE 100
#define ADD_WATER_POINT_X 0.93
#define ADD_WATER_POINT_Y 0.8
typedef enum {
	/**
	 * 宽高均不大于指定的值
	 */
	ZOOM_BY_BOTH,
	/**
	 * 以高为准
	 */
	ZOOM_BY_HEIGHT,
	/**
	 * 以宽为准
	 */
	ZOOM_By_WIDTH,
	/**
	 * 以相对比例小的为准
	 */
	ZOOM_BY_SMALL_TOP,
	/**
	 * 以相对比例大的为准
	 */
	ZOOM_BY_BIG,
	/**
	 * 以相对比例小的为准
	 */
	ZOOM_BY_SMALL_MIDDLE,
	/**
	 * 以相对比例小的为准
	 */
	ZOOM_BY_SMALL_BOTTOM

} ImgZoomType;
typedef enum {
	WATER_TYPE_58, WATER_TYPE_KUCHE, WATER_TYPE_TAOFANG
} WaterType;
int imgZoomInit(ngx_str_t *resouresPath);
int imgZoom(MagickWand *magickWand, int targetWidth, int targetHeight, ImgZoomType zoomType);
int imgAddWater(MagickWand *magickWand, WaterType waterType);
int imgCut(MagickWand *magickWand, int x, int y, int width, int height);
char *getNotFoundImage(int siteId, int *len);
#endif /* IMGZIP_H_ */
